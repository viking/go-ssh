// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// authenticate authenticates with the remote server. See RFC 4252.
func (c *ClientConn) authenticate(session []byte) error {
	// initiate user auth session
	if err := c.WritePacket(MarshalMsg(MsgServiceRequest, ServiceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}
	packet, err := c.readPacket()
	if err != nil {
		return err
	}
	var serviceAccept ServiceAcceptMsg
	if err := unmarshal(&serviceAccept, packet, MsgServiceAccept); err != nil {
		return err
	}
	// during the authentication phase the client first attempts the "none" method
	// then any untried methods suggested by the server.
	tried, remain := make(map[string]bool), make(map[string]bool)
	for auth := ClientAuth(new(noneAuth)); auth != nil; {
		ok, methods, err := auth.auth(session, c.config.User, c.transport, c.config.rand())
		if err != nil {
			return err
		}
		if ok {
			// success
			return nil
		}
		tried[auth.method()] = true
		delete(remain, auth.method())
		for _, meth := range methods {
			if tried[meth] {
				// if we've tried meth already, skip it.
				continue
			}
			remain[meth] = true
		}
		auth = nil
		for _, a := range c.config.Auth {
			if remain[a.method()] {
				auth = a
				break
			}
		}
	}
	return fmt.Errorf("ssh: unable to authenticate, attempted methods %v, no supported methods remain", keys(tried))
}

func keys(m map[string]bool) (s []string) {
	for k := range m {
		s = append(s, k)
	}
	return
}

// HostKeyChecker represents a database of known server host keys.
type HostKeyChecker interface {
	// Check is called during the handshake to check server's
	// public key for unexpected changes. The hostKey argument is
	// in SSH wire format. It can be parsed using
	// ssh.ParsePublicKey. The address before DNS resolution is
	// passed in the addr argument, so the key can also be checked
	// against the hostname.
	Check(addr string, remote net.Addr, algorithm string, hostKey []byte) error
}

// A ClientAuth represents an instance of an RFC 4252 authentication method.
type ClientAuth interface {
	// auth authenticates user over transport t.
	// Returns true if authentication is successful.
	// If authentication is not successful, a []string of alternative
	// method names is returned.
	auth(session []byte, user string, t *transport, rand io.Reader) (bool, []string, error)

	// method returns the RFC 4252 method name.
	method() string
}

// "none" authentication, RFC 4252 section 5.2.
type noneAuth int

func (n *noneAuth) auth(session []byte, user string, t *transport, rand io.Reader) (bool, []string, error) {
	if err := t.WritePacket(MarshalMsg(MsgUserAuthRequest, UserAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "none",
	})); err != nil {
		return false, nil, err
	}

	return handleAuthResponse(t)
}

func (n *noneAuth) method() string {
	return "none"
}

// "password" authentication, RFC 4252 Section 8.
type passwordAuth struct {
	ClientPassword
}

func (p *passwordAuth) auth(session []byte, user string, t *transport, rand io.Reader) (bool, []string, error) {
	type passwordAuthMsg struct {
		User     string
		Service  string
		Method   string
		Reply    bool
		Password string
	}

	pw, err := p.Password(user)
	if err != nil {
		return false, nil, err
	}

	if err := t.WritePacket(MarshalMsg(MsgUserAuthRequest, passwordAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "password",
		Reply:    false,
		Password: pw,
	})); err != nil {
		return false, nil, err
	}

	return handleAuthResponse(t)
}

func (p *passwordAuth) method() string {
	return "password"
}

// A ClientPassword implements access to a client's passwords.
type ClientPassword interface {
	// Password returns the password to use for user.
	Password(user string) (password string, err error)
}

// ClientAuthPassword returns a ClientAuth using password authentication.
func ClientAuthPassword(impl ClientPassword) ClientAuth {
	return &passwordAuth{impl}
}

// ClientKeyring implements access to a client key ring.
type ClientKeyring interface {
	// Key returns the i'th *rsa.Publickey or *dsa.Publickey, or nil if
	// no key exists at i.
	Key(i int) (key interface{}, err error)

	// Sign returns a signature of the given data using the i'th key
	// and the supplied random source.
	Sign(i int, rand io.Reader, data []byte) (sig []byte, err error)
}

// "publickey" authentication, RFC 4252 Section 7.
type publickeyAuth struct {
	ClientKeyring
}

type publickeyAuthMsg struct {
	User    string
	Service string
	Method  string
	// HasSig indicates to the reciver packet that the auth request is signed and
	// should be used for authentication of the request.
	HasSig   bool
	Algoname string
	Pubkey   string
	// Sig is defined as []byte so MarshalMsg will exclude it during validateKey
	Sig []byte `ssh:"rest"`
}

func (p *publickeyAuth) auth(session []byte, user string, t *transport, rand io.Reader) (bool, []string, error) {
	// Authentication is performed in two stages. The first stage sends an
	// enquiry to test if each key is acceptable to the remote. The second
	// stage attempts to authenticate with the valid keys obtained in the
	// first stage.

	var index int
	// a map of public keys to their index in the keyring
	validKeys := make(map[int]interface{})
	for {
		key, err := p.Key(index)
		if err != nil {
			return false, nil, err
		}
		if key == nil {
			// no more keys in the keyring
			break
		}

		if ok, err := p.validateKey(key, user, t); ok {
			validKeys[index] = key
		} else {
			if err != nil {
				return false, nil, err
			}
		}
		index++
	}

	// methods that may continue if this auth is not successful.
	var methods []string
	for i, key := range validKeys {
		pubkey := serializePublickey(key)
		algoname := algoName(key)
		sign, err := p.Sign(i, rand, buildDataSignedForAuth(session, UserAuthRequestMsg{
			User:    user,
			Service: serviceSSH,
			Method:  p.method(),
		}, []byte(algoname), pubkey))
		if err != nil {
			return false, nil, err
		}
		// manually wrap the serialized signature in a string
		s := serializeSignature(algoname, sign)
		sig := make([]byte, stringLength(len(s)))
		MarshalString(sig, s)
		msg := publickeyAuthMsg{
			User:     user,
			Service:  serviceSSH,
			Method:   p.method(),
			HasSig:   true,
			Algoname: algoname,
			Pubkey:   string(pubkey),
			Sig:      sig,
		}
		p := MarshalMsg(MsgUserAuthRequest, msg)
		if err := t.WritePacket(p); err != nil {
			return false, nil, err
		}
		success, methods, err := handleAuthResponse(t)
		if err != nil {
			return false, nil, err
		}
		if success {
			return success, methods, err
		}
	}
	return false, methods, nil
}

// validateKey validates the key provided it is acceptable to the server.
func (p *publickeyAuth) validateKey(key interface{}, user string, t *transport) (bool, error) {
	pubkey := serializePublickey(key)
	algoname := algoName(key)
	msg := publickeyAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   p.method(),
		HasSig:   false,
		Algoname: algoname,
		Pubkey:   string(pubkey),
	}
	if err := t.WritePacket(MarshalMsg(MsgUserAuthRequest, msg)); err != nil {
		return false, err
	}

	return p.confirmKeyAck(key, t)
}

func (p *publickeyAuth) confirmKeyAck(key interface{}, t *transport) (bool, error) {
	pubkey := serializePublickey(key)
	algoname := algoName(key)

	for {
		packet, err := t.readPacket()
		if err != nil {
			return false, err
		}
		switch packet[0] {
		case MsgUserAuthBanner:
			// TODO(gpaul): add callback to present the banner to the user
		case MsgUserAuthPubKeyOk:
			msg := UserAuthPubKeyOkMsg{}
			if err := unmarshal(&msg, packet, MsgUserAuthPubKeyOk); err != nil {
				return false, err
			}
			if msg.Algo != algoname || msg.PubKey != string(pubkey) {
				return false, nil
			}
			return true, nil
		case MsgUserAuthFailure:
			return false, nil
		default:
			return false, UnexpectedMessageError{MsgUserAuthSuccess, packet[0]}
		}
	}
	panic("unreachable")
}

func (p *publickeyAuth) method() string {
	return "publickey"
}

// ClientAuthKeyring returns a ClientAuth using public key authentication.
func ClientAuthKeyring(impl ClientKeyring) ClientAuth {
	return &publickeyAuth{impl}
}

// handleAuthResponse returns whether the preceding authentication request succeeded
// along with a list of remaining authentication methods to try next and
// an error if an unexpected response was received.
func handleAuthResponse(t *transport) (bool, []string, error) {
	for {
		packet, err := t.readPacket()
		if err != nil {
			return false, nil, err
		}

		switch packet[0] {
		case MsgUserAuthBanner:
			// TODO: add callback to present the banner to the user
		case MsgUserAuthFailure:
			msg := UserAuthFailureMsg{}
			if err := unmarshal(&msg, packet, MsgUserAuthFailure); err != nil {
				return false, nil, err
			}
			return false, msg.Methods, nil
		case MsgUserAuthSuccess:
			return true, nil, nil
		case MsgDisconnect:
			return false, nil, io.EOF
		default:
			return false, nil, UnexpectedMessageError{MsgUserAuthSuccess, packet[0]}
		}
	}
	panic("unreachable")
}

// ClientAuthKeyring returns a ClientAuth using public key authentication via
// an agent.
func ClientAuthAgent(agent *AgentClient) ClientAuth {
	return ClientAuthKeyring(&agentKeyring{agent: agent})
}

// agentKeyring implements ClientKeyring.
type agentKeyring struct {
	agent *AgentClient
	keys  []*AgentKey
}

func (kr *agentKeyring) Key(i int) (key interface{}, err error) {
	if kr.keys == nil {
		if kr.keys, err = kr.agent.RequestIdentities(); err != nil {
			return
		}
	}
	if i >= len(kr.keys) {
		return
	}
	return kr.keys[i].Key()
}

func (kr *agentKeyring) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	var key interface{}
	if key, err = kr.Key(i); err != nil {
		return
	}
	if key == nil {
		return nil, errors.New("ssh: key index out of range")
	}
	if sig, err = kr.agent.SignRequest(key, data); err != nil {
		return
	}

	// Unmarshal the signature.

	var ok bool
	if _, sig, ok = parseString(sig); !ok {
		return nil, errors.New("ssh: malformed signature response from agent")
	}
	if sig, _, ok = parseString(sig); !ok {
		return nil, errors.New("ssh: malformed signature response from agent")
	}
	return sig, nil
}

// ClientKeyboardInteractive should prompt the user for the given
// questions.
type ClientKeyboardInteractive interface {
	// Challenge should print the questions, optionally disabling
	// echoing (eg. for passwords), and return all the answers.
	// Challenge may be called multiple times in a single
	// session. After successful authentication, the server may
	// send a challenge with no questions, for which the user and
	// instruction messages should be printed.  RFC 4256 section
	// 3.3 details how the UI should behave for both CLI and
	// GUI environments.
	Challenge(user, instruction string, questions []string, echos []bool) ([]string, error)
}

// ClientAuthKeyboardInteractive returns a ClientAuth using a
// prompt/response sequence controlled by the server.
func ClientAuthKeyboardInteractive(impl ClientKeyboardInteractive) ClientAuth {
	return &keyboardInteractiveAuth{impl}
}

type keyboardInteractiveAuth struct {
	ClientKeyboardInteractive
}

func (c *keyboardInteractiveAuth) method() string {
	return "keyboard-interactive"
}

func (c *keyboardInteractiveAuth) auth(session []byte, user string, t *transport, rand io.Reader) (bool, []string, error) {
	type initiateMsg struct {
		User       string
		Service    string
		Method     string
		Language   string
		Submethods string
	}

	if err := t.WritePacket(MarshalMsg(MsgUserAuthRequest, initiateMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "keyboard-interactive",
	})); err != nil {
		return false, nil, err
	}

	for {
		packet, err := t.readPacket()
		if err != nil {
			return false, nil, err
		}

		// like handleAuthResponse, but with less options.
		switch packet[0] {
		case MsgUserAuthInfoRequest:
			// OK
		case MsgUserAuthFailure:
			var msg UserAuthFailureMsg
			if err := unmarshal(&msg, packet, MsgUserAuthFailure); err != nil {
				return false, nil, err
			}
			return false, msg.Methods, nil
		case MsgUserAuthSuccess:
			return true, nil, nil
		default:
			return false, nil, UnexpectedMessageError{MsgUserAuthInfoRequest, packet[0]}
		}

		var msg UserAuthInfoRequestMsg
		if err := unmarshal(&msg, packet, packet[0]); err != nil {
			return false, nil, err
		}

		// Manually unpack the prompt/echo pairs.
		rest := msg.Prompts
		var prompts []string
		var echos []bool
		for i := 0; i < int(msg.NumPrompts); i++ {
			prompt, r, ok := parseString(rest)
			if !ok || len(r) == 0 {
				return false, nil, errors.New("ssh: prompt format error")
			}
			prompts = append(prompts, string(prompt))
			echos = append(echos, r[0] != 0)
			rest = r[1:]
		}

		if len(rest) != 0 {
			return false, nil, fmt.Errorf("ssh: junk following message %q", rest)
		}

		answers, err := c.Challenge(msg.User, msg.Instruction, prompts, echos)
		if err != nil {
			return false, nil, err
		}

		if len(answers) != len(prompts) {
			return false, nil, errors.New("ssh: not enough answers from keyboard-interactive callback")
		}
		responseLength := 1 + 4
		for _, a := range answers {
			responseLength += stringLength(len(a))
		}
		serialized := make([]byte, responseLength)
		p := serialized
		p[0] = MsgUserAuthInfoResponse
		p = p[1:]
		p = MarshalUint32(p, uint32(len(answers)))
		for _, a := range answers {
			p = MarshalString(p, []byte(a))
		}

		if err := t.WritePacket(serialized); err != nil {
			return false, nil, err
		}
	}
}

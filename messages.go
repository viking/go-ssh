// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"reflect"
)

// These are SSH message type numbers. They are scattered around several
// documents but many were taken from [SSH-PARAMETERS].
const (
	MsgDisconnect     = 1
	MsgIgnore         = 2
	MsgUnimplemented  = 3
	MsgDebug          = 4
	MsgServiceRequest = 5
	MsgServiceAccept  = 6

	MsgKexInit = 20
	MsgNewKeys = 21

	// Diffie-Helman
	MsgKexDHInit  = 30
	MsgKexDHReply = 31

	// Standard authentication messages
	MsgUserAuthRequest  = 50
	MsgUserAuthFailure  = 51
	MsgUserAuthSuccess  = 52
	MsgUserAuthBanner   = 53
	MsgUserAuthPubKeyOk = 60

	// Method specific messages
	MsgUserAuthInfoRequest  = 60
	MsgUserAuthInfoResponse = 61

	MsgGlobalRequest  = 80
	MsgRequestSuccess = 81
	MsgRequestFailure = 82

	// Channel manipulation
	MsgChannelOpen         = 90
	MsgChannelOpenConfirm  = 91
	MsgChannelOpenFailure  = 92
	MsgChannelWindowAdjust = 93
	MsgChannelData         = 94
	MsgChannelExtendedData = 95
	MsgChannelEOF          = 96
	MsgChannelClose        = 97
	MsgChannelRequest      = 98
	MsgChannelSuccess      = 99
	MsgChannelFailure      = 100
)

// SSH messages:
//
// These structures mirror the wire format of the corresponding SSH messages.
// They are marshaled using reflection with the marshal and unmarshal functions
// in this file. The only wrinkle is that a final member of type []byte with a
// ssh tag of "rest" receives the remainder of a packet when unmarshaling.

// See RFC 4253, section 11.1.
type DisconnectMsg struct {
	Reason   uint32
	Message  string
	Language string
}

// See RFC 4253, section 7.1.
type KexInitMsg struct {
	Cookie                  [16]byte
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}

// See RFC 4253, section 8.
type KexDHInitMsg struct {
	X *big.Int
}

type KexDHReplyMsg struct {
	HostKey   []byte
	Y         *big.Int
	Signature []byte
}

// See RFC 4253, section 10.
type ServiceRequestMsg struct {
	Service string
}

// See RFC 4253, section 10.
type ServiceAcceptMsg struct {
	Service string
}

// See RFC 4252, section 5.
type UserAuthRequestMsg struct {
	User    string
	Service string
	Method  string
	Payload []byte `ssh:"rest"`
}

// See RFC 4252, section 5.1
type UserAuthFailureMsg struct {
	Methods        []string
	PartialSuccess bool
}

// See RFC 4256, section 3.2
type UserAuthInfoRequestMsg struct {
	User               string
	Instruction        string
	DeprecatedLanguage string
	NumPrompts         uint32
	Prompts            []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
type ChannelOpenMsg struct {
	ChanType         string
	PeersId          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
type ChannelOpenConfirmMsg struct {
	PeersId          uint32
	MyId             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
type ChannelOpenFailureMsg struct {
	PeersId  uint32
	Reason   RejectionReason
	Message  string
	Language string
}

type ChannelRequestMsg struct {
	PeersId             uint32
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}

// See RFC 4254, section 5.4.
type ChannelRequestSuccessMsg struct {
	PeersId uint32
}

// See RFC 4254, section 5.4.
type ChannelRequestFailureMsg struct {
	PeersId uint32
}

// See RFC 4254, section 5.3
type ChannelCloseMsg struct {
	PeersId uint32
}

// See RFC 4254, section 5.3
type ChannelEOFMsg struct {
	PeersId uint32
}

// See RFC 4254, section 4
type GlobalRequestMsg struct {
	Type      string
	WantReply bool
}

// See RFC 4254, section 4
type GlobalRequestSuccessMsg struct {
	Data []byte `ssh:"rest"`
}

// See RFC 4254, section 4
type GlobalRequestFailureMsg struct {
	Data []byte `ssh:"rest"`
}

// See RFC 4254, section 5.2
type WindowAdjustMsg struct {
	PeersId         uint32
	AdditionalBytes uint32
}

// See RFC 4252, section 7
type UserAuthPubKeyOkMsg struct {
	Algo   string
	PubKey string
}

// unmarshal parses the SSH wire data in packet into out using reflection.
// expectedType is the expected SSH message type. It either returns nil on
// success, or a ParseError or UnexpectedMessageError on error.
func unmarshal(out interface{}, packet []byte, expectedType uint8) error {
	if len(packet) == 0 {
		return ParseError{expectedType}
	}
	if packet[0] != expectedType {
		return UnexpectedMessageError{expectedType, packet[0]}
	}
	packet = packet[1:]

	v := reflect.ValueOf(out).Elem()
	structType := v.Type()
	var ok bool
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		t := field.Type()
		switch t.Kind() {
		case reflect.Bool:
			if len(packet) < 1 {
				return ParseError{expectedType}
			}
			field.SetBool(packet[0] != 0)
			packet = packet[1:]
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic("array of non-uint8")
			}
			if len(packet) < t.Len() {
				return ParseError{expectedType}
			}
			for j, n := 0, t.Len(); j < n; j++ {
				field.Index(j).Set(reflect.ValueOf(packet[j]))
			}
			packet = packet[t.Len():]
		case reflect.Uint32:
			var u32 uint32
			if u32, packet, ok = parseUint32(packet); !ok {
				return ParseError{expectedType}
			}
			field.SetUint(uint64(u32))
		case reflect.String:
			var s []byte
			if s, packet, ok = parseString(packet); !ok {
				return ParseError{expectedType}
			}
			field.SetString(string(s))
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if structType.Field(i).Tag.Get("ssh") == "rest" {
					field.Set(reflect.ValueOf(packet))
					packet = nil
				} else {
					var s []byte
					if s, packet, ok = parseString(packet); !ok {
						return ParseError{expectedType}
					}
					field.Set(reflect.ValueOf(s))
				}
			case reflect.String:
				var nl []string
				if nl, packet, ok = parseNameList(packet); !ok {
					return ParseError{expectedType}
				}
				field.Set(reflect.ValueOf(nl))
			default:
				panic("slice of unknown type")
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				if n, packet, ok = parseInt(packet); !ok {
					return ParseError{expectedType}
				}
				field.Set(reflect.ValueOf(n))
			} else {
				panic("pointer to unknown type")
			}
		default:
			panic("unknown type")
		}
	}

	if len(packet) != 0 {
		return ParseError{expectedType}
	}

	return nil
}

// marshal serializes the message in msg, using the given message type.
func marshal(msgType uint8, msg interface{}) []byte {
	out := make([]byte, 1, 64)
	out[0] = msgType

	v := reflect.ValueOf(msg)
	for i, n := 0, v.NumField(); i < n; i++ {
		field := v.Field(i)
		switch t := field.Type(); t.Kind() {
		case reflect.Bool:
			var v uint8
			if field.Bool() {
				v = 1
			}
			out = append(out, v)
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic("array of non-uint8")
			}
			for j, l := 0, t.Len(); j < l; j++ {
				out = append(out, uint8(field.Index(j).Uint()))
			}
		case reflect.Uint32:
			out = appendU32(out, uint32(field.Uint()))
		case reflect.String:
			s := field.String()
			out = appendInt(out, len(s))
			out = append(out, s...)
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if v.Type().Field(i).Tag.Get("ssh") != "rest" {
					out = appendInt(out, field.Len())
				}
				out = append(out, field.Bytes()...)
			case reflect.String:
				offset := len(out)
				out = appendU32(out, 0)
				if n := field.Len(); n > 0 {
					for j := 0; j < n; j++ {
						f := field.Index(j)
						if j != 0 {
							out = append(out, ',')
						}
						out = append(out, f.String()...)
					}
					// overwrite length value
					binary.BigEndian.PutUint32(out[offset:], uint32(len(out)-offset-4))
				}
			default:
				panic("slice of unknown type")
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				nValue := reflect.ValueOf(&n)
				nValue.Elem().Set(field)
				needed := intLength(n)
				oldLength := len(out)

				if cap(out)-len(out) < needed {
					newOut := make([]byte, len(out), 2*(len(out)+needed))
					copy(newOut, out)
					out = newOut
				}
				out = out[:oldLength+needed]
				marshalInt(out[oldLength:], n)
			} else {
				panic("pointer to unknown type")
			}
		}
	}

	return out
}

var bigOne = big.NewInt(1)

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = in[4 : 4+length]
	rest = in[4+length:]
	ok = true
	return
}

var (
	comma         = []byte{','}
	emptyNameList = []string{}
)

func parseNameList(in []byte) (out []string, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	if len(contents) == 0 {
		out = emptyNameList
		return
	}
	parts := bytes.Split(contents, comma)
	out = make([]string, len(parts))
	for i, part := range parts {
		out[i] = string(part)
	}
	return
}

func parseInt(in []byte) (out *big.Int, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	out = new(big.Int)

	if len(contents) > 0 && contents[0]&0x80 == 0x80 {
		// This is a negative number
		notBytes := make([]byte, len(contents))
		for i := range notBytes {
			notBytes[i] = ^contents[i]
		}
		out.SetBytes(notBytes)
		out.Add(out, bigOne)
		out.Neg(out)
	} else {
		// Positive number
		out.SetBytes(contents)
	}
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseUint64(in []byte) (uint64, []byte, bool) {
	if len(in) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(in), in[8:], true
}

func nameListLength(namelist []string) int {
	length := 4 /* uint32 length prefix */
	for i, name := range namelist {
		if i != 0 {
			length++ /* comma */
		}
		length += len(name)
	}
	return length
}

func intLength(n *big.Int) int {
	length := 4 /* length bytes */
	if n.Sign() < 0 {
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bitLen := nMinus1.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0xff padding
			length++
		}
		length += (bitLen + 7) / 8
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bitLen := n.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0x00 padding
			length++
		}
		length += (bitLen + 7) / 8
	}

	return length
}

func marshalUint32(to []byte, n uint32) []byte {
	binary.BigEndian.PutUint32(to, n)
	return to[4:]
}

func marshalUint64(to []byte, n uint64) []byte {
	binary.BigEndian.PutUint64(to, n)
	return to[8:]
}

func marshalInt(to []byte, n *big.Int) []byte {
	lengthBytes := to
	to = to[4:]
	length := 0

	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll subtract 1 and invert. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			to[0] = 0xff
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with a 0x00 in order to
			// stop it looking like a negative number.
			to[0] = 0
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	}

	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)
	return to
}

func writeInt(w io.Writer, n *big.Int) {
	length := intLength(n)
	buf := make([]byte, length)
	marshalInt(buf, n)
	w.Write(buf)
}

func writeString(w io.Writer, s []byte) {
	var lengthBytes [4]byte
	lengthBytes[0] = byte(len(s) >> 24)
	lengthBytes[1] = byte(len(s) >> 16)
	lengthBytes[2] = byte(len(s) >> 8)
	lengthBytes[3] = byte(len(s))
	w.Write(lengthBytes[:])
	w.Write(s)
}

func stringLength(n int) int {
	return 4 + n
}

func marshalString(to []byte, s []byte) []byte {
	to[0] = byte(len(s) >> 24)
	to[1] = byte(len(s) >> 16)
	to[2] = byte(len(s) >> 8)
	to[3] = byte(len(s))
	to = to[4:]
	copy(to, s)
	return to[len(s):]
}

var bigIntType = reflect.TypeOf((*big.Int)(nil))

// Decode a packet into its corresponding message.
func decode(packet []byte) (interface{}, error) {
	var msg interface{}
	switch packet[0] {
	case MsgDisconnect:
		msg = new(DisconnectMsg)
	case MsgServiceRequest:
		msg = new(ServiceRequestMsg)
	case MsgServiceAccept:
		msg = new(ServiceAcceptMsg)
	case MsgKexInit:
		msg = new(KexInitMsg)
	case MsgKexDHInit:
		msg = new(KexDHInitMsg)
	case MsgKexDHReply:
		msg = new(KexDHReplyMsg)
	case MsgUserAuthRequest:
		msg = new(UserAuthRequestMsg)
	case MsgUserAuthFailure:
		msg = new(UserAuthFailureMsg)
	case MsgUserAuthPubKeyOk:
		msg = new(UserAuthPubKeyOkMsg)
	case MsgGlobalRequest:
		msg = new(GlobalRequestMsg)
	case MsgRequestSuccess:
		msg = new(GlobalRequestSuccessMsg)
	case MsgRequestFailure:
		msg = new(GlobalRequestFailureMsg)
	case MsgChannelOpen:
		msg = new(ChannelOpenMsg)
	case MsgChannelOpenConfirm:
		msg = new(ChannelOpenConfirmMsg)
	case MsgChannelOpenFailure:
		msg = new(ChannelOpenFailureMsg)
	case MsgChannelWindowAdjust:
		msg = new(WindowAdjustMsg)
	case MsgChannelEOF:
		msg = new(ChannelEOFMsg)
	case MsgChannelClose:
		msg = new(ChannelCloseMsg)
	case MsgChannelRequest:
		msg = new(ChannelRequestMsg)
	case MsgChannelSuccess:
		msg = new(ChannelRequestSuccessMsg)
	case MsgChannelFailure:
		msg = new(ChannelRequestFailureMsg)
	default:
		return nil, UnexpectedMessageError{0, packet[0]}
	}
	if err := unmarshal(msg, packet, packet[0]); err != nil {
		return nil, err
	}
	return msg, nil
}

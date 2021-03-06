// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Listen requests the remote peer open a listening socket
// on addr. Incoming connections will be available by calling
// Accept on the returned net.Listener.
func (c *ClientConn) Listen(n, addr string) (net.Listener, error) {
	laddr, err := net.ResolveTCPAddr(n, addr)
	if err != nil {
		return nil, err
	}
	return c.ListenTCP(laddr)
}

// RFC 4254 7.1
type channelForwardMsg struct {
	Message   string
	WantReply bool
	raddr     string
	rport     uint32
}

// ListenTCP requests the remote peer open a listening socket
// on laddr. Incoming connections will be available by calling
// Accept on the returned net.Listener.
func (c *ClientConn) ListenTCP(laddr *net.TCPAddr) (net.Listener, error) {
	m := channelForwardMsg{
		"tcpip-forward",
		true, // sendGlobalRequest waits for a reply
		laddr.IP.String(),
		uint32(laddr.Port),
	}
	// send message
	resp, err := c.sendGlobalRequest(m)
	if err != nil {
		return nil, err
	}

	// If the original port was 0, then the remote side will
	// supply a real port number in the response.
	if laddr.Port == 0 {
		port, _, ok := parseUint32(resp.Data)
		if !ok {
			return nil, errors.New("unable to parse response")
		}
		laddr.Port = int(port)
	}

	// Register this forward, using the port number we obtained.
	//
	// This does not work on OpenSSH < 6.0, which will send a
	// ChannelOpenMsg with port number 0, rather than the actual
	// port number.
	ch := c.forwardList.add(*laddr)

	return &tcpListener{laddr, c, ch}, nil
}

// forwardList stores a mapping between remote
// forward requests and the tcpListeners.
type forwardList struct {
	sync.Mutex
	entries []forwardEntry
}

// forwardEntry represents an established mapping of a laddr on a
// remote ssh server to a channel connected to a tcpListener.
type forwardEntry struct {
	laddr net.TCPAddr
	c     chan forward
}

// forward represents an incoming forwarded tcpip connection. The
// arguments to add/remove/lookup should be address as specified in
// the original forward-request.
type forward struct {
	c     *ClientChan  // the ssh client channel underlying this forward
	raddr *net.TCPAddr // the raddr of the incoming connection
}

func (l *forwardList) add(addr net.TCPAddr) chan forward {
	l.Lock()
	defer l.Unlock()
	f := forwardEntry{
		addr,
		make(chan forward, 1),
	}
	l.entries = append(l.entries, f)
	return f.c
}

func (l *forwardList) remove(addr net.TCPAddr) {
	l.Lock()
	defer l.Unlock()
	for i, f := range l.entries {
		if addr.IP.Equal(f.laddr.IP) && addr.Port == f.laddr.Port {
			l.entries = append(l.entries[:i], l.entries[i+1:]...)
			return
		}
	}
}

func (l *forwardList) lookup(addr net.TCPAddr) (chan forward, bool) {
	l.Lock()
	defer l.Unlock()
	for _, f := range l.entries {
		if addr.IP.Equal(f.laddr.IP) && addr.Port == f.laddr.Port {
			return f.c, true
		}
	}
	return nil, false
}

type tcpListener struct {
	laddr *net.TCPAddr

	conn *ClientConn
	in   <-chan forward
}

// Accept waits for and returns the next connection to the listener.
func (l *tcpListener) Accept() (net.Conn, error) {
	s, ok := <-l.in
	if !ok {
		return nil, io.EOF
	}
	return &tcpChanConn{
		tcpChan: &tcpChan{
			ClientChan: s.c,
			Reader:     s.c.stdout,
			Writer:     s.c.stdin,
		},
		laddr: l.laddr,
		raddr: s.raddr,
	}, nil
}

// Close closes the listener.
func (l *tcpListener) Close() error {
	m := channelForwardMsg{
		"cancel-tcpip-forward",
		true,
		l.laddr.IP.String(),
		uint32(l.laddr.Port),
	}
	l.conn.forwardList.remove(*l.laddr)
	if _, err := l.conn.sendGlobalRequest(m); err != nil {
		return err
	}
	return nil
}

// Addr returns the listener's network address.
func (l *tcpListener) Addr() net.Addr {
	return l.laddr
}

// Dial initiates a connection to the addr from the remote host.
// addr is resolved using net.ResolveTCPAddr before connection.
// This could allow an observer to observe the DNS name of the
// remote host. Consider using ssh.DialTCP to avoid this.
func (c *ClientConn) Dial(n, addr string) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr(n, addr)
	if err != nil {
		return nil, err
	}
	return c.DialTCP(n, nil, raddr)
}

// DialTCP connects to the remote address raddr on the network net,
// which must be "tcp", "tcp4", or "tcp6".  If laddr is not nil, it is used
// as the local address for the connection.
func (c *ClientConn) DialTCP(n string, laddr, raddr *net.TCPAddr) (net.Conn, error) {
	if laddr == nil {
		laddr = &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}
	ch, err := c.dial(laddr.IP.String(), laddr.Port, raddr.IP.String(), raddr.Port)
	if err != nil {
		return nil, err
	}
	return &tcpChanConn{
		tcpChan: ch,
		laddr:   laddr,
		raddr:   raddr,
	}, nil
}

// RFC 4254 7.2
type channelOpenDirectMsg struct {
	ChanType      string
	PeersId       uint32
	PeersWindow   uint32
	MaxPacketSize uint32
	raddr         string
	rport         uint32
	laddr         string
	lport         uint32
}

// dial opens a direct-tcpip connection to the remote server. laddr and raddr are passed as
// strings and are expected to be resolveable at the remote end.
func (c *ClientConn) dial(laddr string, lport int, raddr string, rport int) (*tcpChan, error) {
	ch := c.newChan(c.transport)
	if err := c.WritePacket(MarshalMsg(MsgChannelOpen, channelOpenDirectMsg{
		ChanType:      "direct-tcpip",
		PeersId:       ch.localId,
		PeersWindow:   1 << 14,
		MaxPacketSize: 1 << 15, // RFC 4253 6.1
		raddr:         raddr,
		rport:         uint32(rport),
		laddr:         laddr,
		lport:         uint32(lport),
	})); err != nil {
		c.chanList.remove(ch.localId)
		return nil, err
	}
	if err := ch.WaitForChannelOpenResponse(); err != nil {
		c.chanList.remove(ch.localId)
		return nil, fmt.Errorf("ssh: unable to open direct tcpip connection: %v", err)
	}
	return &tcpChan{
		ClientChan: ch,
		Reader:     ch.stdout,
		Writer:     ch.stdin,
	}, nil
}

type tcpChan struct {
	*ClientChan // the backing channel
	io.Reader
	io.Writer
}

// tcpChanConn fulfills the net.Conn interface without
// the tcpChan having to hold laddr or raddr directly.
type tcpChanConn struct {
	*tcpChan
	laddr, raddr net.Addr
}

// LocalAddr returns the local network address.
func (t *tcpChanConn) LocalAddr() net.Addr {
	return t.laddr
}

// RemoteAddr returns the remote network address.
func (t *tcpChanConn) RemoteAddr() net.Addr {
	return t.raddr
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (t *tcpChanConn) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

// SetReadDeadline sets the read deadline.
// A zero value for t means Read will not time out.
// After the deadline, the error from Read will implement net.Error
// with Timeout() == true.
func (t *tcpChanConn) SetReadDeadline(deadline time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

// SetWriteDeadline exists to satisfy the net.Conn interface
// but is not implemented by this type.  It always returns an error.
func (t *tcpChanConn) SetWriteDeadline(deadline time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

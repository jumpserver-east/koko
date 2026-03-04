// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
)

// OpenChannelError is returned if the other side rejects an
// OpenChannel request.
type OpenChannelError struct {
	Reason  RejectionReason
	Message string
}

func (e *OpenChannelError) Error() string {
	return fmt.Sprintf("ssh: rejected: %s (%s)", e.Reason, e.Message)
}

// ConnMetadata holds metadata for the connection.
type ConnMetadata interface {
	// User returns the user ID for this connection.
	User() string

	// SessionID returns the session hash, also denoted by H.
	SessionID() []byte

	// ClientVersion returns the client's version string as hashed
	// into the session ID.
	ClientVersion() []byte

	// ServerVersion returns the server's version string as hashed
	// into the session ID.
	ServerVersion() []byte

	// RemoteAddr returns the remote address for this connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address for this connection.
	LocalAddr() net.Addr
}

// Conn represents an SSH connection for both server and client roles.
// Conn is the basis for implementing an application layer, such
// as ClientConn, which implements the traditional shell access for
// clients.
type Conn interface {
	ConnMetadata

	// SendRequest sends a global request, and returns the
	// reply. If wantReply is true, it returns the response status
	// and payload. See also RFC 4254, section 4.
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)

	// OpenChannel tries to open an channel. If the request is
	// rejected, it returns *OpenChannelError. On success it returns
	// the SSH Channel and a Go channel for incoming, out-of-band
	// requests. The Go channel must be serviced, or the
	// connection will hang.
	OpenChannel(name string, data []byte) (Channel, <-chan *Request, error)

	// Close closes the underlying network connection
	Close() error

	// Wait blocks until the connection has shut down, and returns the
	// error causing the shutdown.
	Wait() error

	// TODO(hanwen): consider exposing:
	//   RequestKeyChange
	//   Disconnect
}

// AlgorithmsConnMetadata is a ConnMetadata that can return the algorithms
// negotiated between client and server.
type AlgorithmsConnMetadata interface {
	ConnMetadata
	Algorithms() NegotiatedAlgorithms
}

// DiscardRequests consumes and rejects all requests from the
// passed-in channel.
func DiscardRequests(in <-chan *Request) {
	for req := range in {
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// A connection represents an incoming connection.
type connection struct {
	transport *handshakeTransport
	sshConn

	// The connection protocol.
	*mux

	// GM/T 0129 password auth context, set during challenge-response.
	gmChallenge []byte
	gmSalt      []byte
}

// gmAuthDataStore stores GM/T 0129 challenge/salt keyed by hex session ID,
// so that higher-level wrappers (e.g. gliderlabs/ssh) that only expose a
// string session ID can retrieve them via GetGMAuthDataBySessionID.
var gmAuthDataStore sync.Map

type gmAuthData struct {
	challenge, salt []byte
}

func storeGMAuthData(sessionID, challenge, salt []byte) {
	gmAuthDataStore.Store(hex.EncodeToString(sessionID), &gmAuthData{challenge, salt})
}

func clearGMAuthData(sessionID []byte) {
	gmAuthDataStore.Delete(hex.EncodeToString(sessionID))
}

// GetGMAuthData returns the GM/T 0129-2023 challenge and salt for the current
// password authentication attempt. PasswordCallback implementations can use this
// to detect GM password auth and verify the response:
//
//	response == SM3(challenge || SM3(storedPassword) || salt)
//
// Returns ok=false if the current auth is not a GM password challenge-response.
func GetGMAuthData(conn ConnMetadata) (challenge, salt []byte, ok bool) {
	if c, is := conn.(*connection); is && c.gmChallenge != nil {
		return c.gmChallenge, c.gmSalt, true
	}
	return nil, nil, false
}

// GetGMAuthDataBySessionID returns the GM/T 0129-2023 challenge and salt
// using a hex-encoded session ID. This is intended for use with higher-level
// SSH server wrappers (e.g. gliderlabs/ssh) where ConnMetadata is not directly
// available but a string session ID is.
func GetGMAuthDataBySessionID(sessionID string) (challenge, salt []byte, ok bool) {
	v, loaded := gmAuthDataStore.Load(sessionID)
	if !loaded {
		return nil, nil, false
	}
	d := v.(*gmAuthData)
	return d.challenge, d.salt, true
}

func (c *connection) Close() error {
	return c.sshConn.conn.Close()
}

// sshConn provides net.Conn metadata, but disallows direct reads and
// writes.
type sshConn struct {
	conn net.Conn

	user          string
	sessionID     []byte
	clientVersion []byte
	serverVersion []byte
	algorithms    NegotiatedAlgorithms
}

func dup(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (c *sshConn) User() string {
	return c.user
}

func (c *sshConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *sshConn) Close() error {
	return c.conn.Close()
}

func (c *sshConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sshConn) SessionID() []byte {
	return dup(c.sessionID)
}

func (c *sshConn) ClientVersion() []byte {
	return dup(c.clientVersion)
}

func (c *sshConn) ServerVersion() []byte {
	return dup(c.serverVersion)
}

func (c *sshConn) Algorithms() NegotiatedAlgorithms {
	return c.algorithms
}

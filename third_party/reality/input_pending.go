package reality

import "net"

// Reality specific file: whether the client's next bytes already wait, as
// a target that reads after its handshake would find them.

// inputPending reports whether client data is buffered: read already, or
// held by the kernel for the socket under the connection.
func (c *Conn) inputPending() bool {
	if c.rawInput != nil && c.rawInput.Len() > 0 {
		return true
	}
	conn := c.conn
	for {
		switch inner := conn.(type) {
		case interface{ NetConn() net.Conn }:
			conn = inner.NetConn()
			continue
		case interface{ Raw() net.Conn }: // a PROXY protocol connection
			conn = inner.Raw()
			continue
		case interface {
			RawConn() net.Conn
			Splice() bool
		}: // a FinalMask wrapper
			if !inner.Splice() {
				// It re-encodes the stream: the socket's bytes are not the
				// client's data, so only what was read counts.
				return false
			}
			conn = inner.RawConn()
			continue
		}
		break
	}
	return socketInputPending(conn)
}

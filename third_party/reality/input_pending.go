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
				// It may re-encode the stream (Sudoku), so the socket's
				// bytes need not be the client's data and only what was
				// read counts. The server-side fragment mask also lands
				// here: it reports false for its writes, though its reads
				// pass through.
				return false
			}
			conn = inner.RawConn()
			continue
		}
		break
	}
	return socketInputPending(conn)
}

//go:build !linux

package reality

import "net"

// socketInputPending is known only on Linux; elsewhere only bytes already
// read count.
func socketInputPending(net.Conn) bool { return false }

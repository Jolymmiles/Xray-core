package reality

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketInputPending asks the kernel how many bytes wait on conn's socket.
func socketInputPending(conn net.Conn) bool {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	pending := 0
	if err := raw.Control(func(fd uintptr) {
		if n, err := unix.IoctlGetInt(int(fd), unix.SIOCINQ); err == nil {
			pending = n
		}
	}); err != nil {
		return false
	}
	return pending > 0
}

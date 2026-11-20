//go:build unix || windows

package net_test

import (
	"errors"
	"io"
	stdnet "net"
	"os"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// A UDP socket refuses a datagram too long for it with EMSGSIZE, however Go
// wraps the error; no other error counts.
func TestIsMessageTooLong(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&stdnet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EMSGSIZE)}, true},
		{os.NewSyscallError("recvfrom", syscall.EMSGSIZE), true},
		{syscall.EMSGSIZE, true},
		{&stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}, false},
		{io.EOF, false},
		{errors.New("message too long"), false},
		{nil, false},
	} {
		if got := net.IsMessageTooLong(c.err); got != c.want {
			t.Errorf("IsMessageTooLong(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

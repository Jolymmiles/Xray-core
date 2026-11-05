//go:build windows

package net_test

import (
	stdnet "net"
	"os"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/windows"
)

// Windows refuses a datagram too long for the socket, and fails a read that
// cut one short, with WSAEMSGSIZE, which Go does not map to syscall.EMSGSIZE.
func TestIsMessageTooLongOnWindows(t *testing.T) {
	for _, err := range []error{
		&stdnet.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecvfrom", windows.WSAEMSGSIZE)},
		&stdnet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("wsasendto", windows.WSAEMSGSIZE)},
	} {
		if !net.IsMessageTooLong(err) {
			t.Errorf("IsMessageTooLong(%v) = false, want true", err)
		}
	}
	if !net.IsTruncated(windows.MSG_TRUNC) || net.IsTruncated(0) {
		t.Errorf("IsTruncated does not tell MSG_TRUNC")
	}
}

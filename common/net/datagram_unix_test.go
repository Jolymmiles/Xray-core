//go:build unix

package net_test

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

// A read marks a datagram it cut short with MSG_TRUNC among its flags.
func TestIsTruncated(t *testing.T) {
	for _, c := range []struct {
		flags int
		want  bool
	}{
		{unix.MSG_TRUNC, true},
		{unix.MSG_TRUNC | unix.MSG_CTRUNC, true},
		{unix.MSG_CTRUNC, false},
		{0, false},
	} {
		if got := net.IsTruncated(c.flags); got != c.want {
			t.Errorf("IsTruncated(%#x) = %v, want %v", c.flags, got, c.want)
		}
	}
}

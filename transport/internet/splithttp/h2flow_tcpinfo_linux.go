//go:build linux

package splithttp

import (
	"net"
	"syscall"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sys/unix"
)

func rawTCP(c net.Conn) syscall.RawConn {
	for range 8 {
		switch v := c.(type) {
		case *net.TCPConn:
			rc, err := v.SyscallConn()
			if err != nil {
				return nil
			}
			return rc
		case *stat.CounterConnection:
			c = v.Connection
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		case interface{ Raw() net.Conn }:
			c = v.Raw()
		default:
			return nil
		}
	}
	return nil
}

func readTCPStats(rc syscall.RawConn) (s tcpStats, ok bool) {
	if rc == nil {
		return
	}
	rc.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			return
		}
		s.rtt = time.Duration(info.Rtt) * time.Microsecond
		s.minRTT = time.Duration(info.Min_rtt) * time.Microsecond
		ok = s.rtt > 0
	})
	return
}

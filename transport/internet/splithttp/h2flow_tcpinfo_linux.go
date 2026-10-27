//go:build linux

package splithttp

import (
	"net"
	"reflect"
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
			if c = embeddedConn(c); c == nil {
				return nil
			}
		}
	}
	return nil
}

// embeddedConn is the net.Conn a wrapper embeds, such as finalmask's, which
// offer no NetConn: the kernel's view of the TCP socket under a mask is still
// that connection's round trip and what it has in flight.
func embeddedConn(c net.Conn) net.Conn {
	v := reflect.ValueOf(c)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	f := v.FieldByName("Conn")
	if !f.IsValid() || !f.CanInterface() {
		return nil
	}
	inner, _ := f.Interface().(net.Conn)
	return inner
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
		s.rttVar = time.Duration(info.Rttvar) * time.Microsecond
		s.inFlight = int64(info.Unacked) * int64(info.Snd_mss)
		ok = s.rtt > 0
	})
	return
}

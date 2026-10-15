package net

import (
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/log"
)

// The longest UDP payload an IP packet holds: of its 65535 bytes, the UDP
// header takes 8 and an IPv4 header 20, while the IPv6 header is not counted.
// A socket refuses a longer datagram, and no IP header can state its length.
const (
	MaxUDPPayloadIPv4 = 65535 - 20 - 8
	MaxUDPPayloadIPv6 = 65535 - 8
)

// MaxUDPPayload returns the longest UDP payload of an IP packet to addr: that
// of IPv6 for a *UDPAddr without an IPv4 address, else that of IPv4.
func MaxUDPPayload(addr Addr) int32 {
	if udpAddr, ok := addr.(*UDPAddr); ok && udpAddr != nil && udpAddr.IP.To4() == nil {
		return MaxUDPPayloadIPv6
	}
	return MaxUDPPayloadIPv4
}

// DropLog limits the debug log of the datagrams that one session, socket or
// writer drops: it logs the first, then at most one a second, as a drop is
// per datagram. The caller writes the log, so that it names the component
// that dropped the datagram and, with its context, the session.
type DropLog struct {
	last atomic.Int64 // when a drop was last logged, in Unix nanoseconds
}

// Due reports whether to log a drop now: debug logging is on, and the drop is
// the first or the last one logged is a second old.
func (l *DropLog) Due() bool {
	if !log.ShouldLog(log.Severity_Debug) {
		return false
	}
	now := time.Now().UnixNano()
	last := l.last.Load()
	if last != 0 && now-last < int64(time.Second) {
		return false
	}
	return l.last.CompareAndSwap(last, now)
}

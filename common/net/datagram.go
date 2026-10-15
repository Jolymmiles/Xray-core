package net

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
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

// lastDropLog is when LogDroppedDatagram last logged, in Unix nanoseconds.
var lastDropLog atomic.Int64

// LogDroppedDatagram logs at debug level that a datagram of size bytes, or of
// unknown size if size is negative, was dropped, and why, so that a route
// whose socket refuses every datagram does not pass for a healthy session
// without replies. It logs once a second at most, as a drop is per datagram.
func LogDroppedDatagram(ctx context.Context, size int, reason string) {
	now := time.Now().UnixNano()
	last := lastDropLog.Load()
	if now-last < int64(time.Second) || !lastDropLog.CompareAndSwap(last, now) {
		return
	}
	if size < 0 {
		errors.LogDebug(ctx, "dropped a UDP datagram: ", reason, " (logged once a second at most)")
		return
	}
	errors.LogDebug(ctx, "dropped a UDP datagram of ", size, " bytes: ", reason, " (logged once a second at most)")
}

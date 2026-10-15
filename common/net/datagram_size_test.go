package net

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/log"
)

func TestMaxUDPPayload(t *testing.T) {
	for _, c := range []struct {
		addr Addr
		want int32
	}{
		{&UDPAddr{IP: IP{192, 0, 2, 1}}, 65507},
		{&UDPAddr{IP: ParseIP("::ffff:192.0.2.1")}, 65507},
		{&UDPAddr{IP: ParseIP("2001:db8::1")}, 65527},
		{(*UDPAddr)(nil), 65507},
		{&TCPAddr{IP: ParseIP("2001:db8::1")}, 65507},
		{nil, 65507},
	} {
		if got := MaxUDPPayload(c.addr); got != c.want {
			t.Errorf("MaxUDPPayload(%v) = %d, want %d", c.addr, got, c.want)
		}
	}
}

// debugLog accepts every message, so that debug logging is on.
type debugLog struct{}

func (debugLog) Handle(log.Message) {}

// silentLog accepts no message, as when no log handler is registered.
type silentLog struct{}

func (silentLog) Handle(log.Message)        {}
func (silentLog) Enabled(log.Severity) bool { return false }

// A drop is per datagram, so its log must not follow a sender's rate: a
// DropLog lets the first drop be logged, then one a second, and only while
// debug logging is on, so that a drop with the log off does not take the turn
// of the next.
func TestDropLogLetsTheFirstDropThenOneASecond(t *testing.T) {
	log.RegisterHandler(silentLog{})
	t.Cleanup(func() { log.RegisterHandler(silentLog{}) })
	var drops DropLog
	if drops.Due() {
		t.Fatal("a drop is due with debug logging off")
	}
	log.RegisterHandler(debugLog{})
	if !drops.Due() {
		t.Fatal("the first drop is not due")
	}
	if drops.Due() {
		t.Fatal("a second drop within the second is due")
	}
	drops.last.Store(time.Now().Add(-time.Second).UnixNano())
	if !drops.Due() {
		t.Fatal("a drop a second later is not due")
	}
	var other DropLog
	if !other.Due() {
		t.Fatal("the first drop of another DropLog is not due")
	}
}

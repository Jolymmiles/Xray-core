package net

import (
	"context"
	"testing"
	"time"
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

// A drop is per datagram, so its log must not flood: it logs once a second.
func TestLogDroppedDatagramLogsOnceASecond(t *testing.T) {
	lastDropLog.Store(0)
	LogDroppedDatagram(context.Background(), 9000, "test")
	logged := lastDropLog.Load()
	if logged == 0 {
		t.Fatal("the first drop was not logged")
	}
	LogDroppedDatagram(context.Background(), 9000, "test")
	if lastDropLog.Load() != logged {
		t.Fatal("a second drop within the second was logged")
	}
	lastDropLog.Store(time.Now().Add(-time.Second).UnixNano())
	LogDroppedDatagram(context.Background(), -1, "test")
	if lastDropLog.Load() <= logged {
		t.Fatal("a drop a second later was not logged")
	}
}

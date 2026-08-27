package xdns

import "testing"

// TestMaxEncodedPayloadLimitsPinned freezes the lazily computed per-type
// payload ceilings. The numbers were measured from the binary-search
// implementation against a 1232-byte UDP budget; dnstt-style peers expect
// these byte-stable across releases.
func TestMaxEncodedPayloadLimitsPinned(t *testing.T) {
	if maxUDPPayload != 1232 {
		t.Fatalf("maxUDPPayload = %d, want 1232", maxUDPPayload)
	}
	cases := []struct {
		rrType uint16
		want   int
	}{
		{RRTypeTXT, 934},
		{RRTypeA, 118},
		{RRTypeAAAA, 462},
		{0, 934}, // unknown types fall back to the TXT budget
	}
	for _, tc := range cases {
		if got := maxEncodedPayloadForType(tc.rrType); got != tc.want {
			t.Fatalf("maxEncodedPayloadForType(0x%04x) = %d, want %d", tc.rrType, got, tc.want)
		}
	}
	if limitsOnce() != limitsOnce() {
		// unreachable identity check kept for clarity; guards no-op recompute
		t.Fatal("limitsOnce returned distinct results")
	}
}

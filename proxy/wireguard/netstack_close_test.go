package wireguard

import (
	"net/netip"
	"testing"
)

// wireguard-go closes the TUN device itself when the device shuts down, for
// example after the bind fails to open on a port in use, and the server's own
// Close closes it again. A second Close must not panic the process.
func TestNetTUNCloseIsIdempotent(t *testing.T) {
	device, _, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1420, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("second Close panicked: %v", recovered)
		}
	}()
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
}

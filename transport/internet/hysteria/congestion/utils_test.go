package congestion

import (
	"testing"

	quiccongestion "github.com/apernet/quic-go/congestion"
)

func TestBBRSeedPacketSizePreventsPMTUDecreasePanic(t *testing.T) {
	tests := []struct {
		name             string
		quicSize, byAddr quiccongestion.ByteCount
		want             quiccongestion.ByteCount
	}{
		{name: "QUIC smaller", quicSize: 1200, byAddr: 1252, want: 1200},
		{name: "address smaller", quicSize: 1252, byAddr: 1200, want: 1200},
		{name: "unknown QUIC size", quicSize: 0, byAddr: 1200, want: 1200},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := seedPacketSize(test.quicSize, test.byAddr); got != test.want {
				t.Fatalf("seedPacketSize(%d, %d) = %d, want %d", test.quicSize, test.byAddr, got, test.want)
			}
		})
	}
}

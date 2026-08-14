package brutal

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

func feedAckRate(disableLossCompensation bool, ackCount, lossCount int) float64 {
	b := NewBrutalSender(1000000, disableLossCompensation)
	acked := make([]congestion.AckedPacketInfo, ackCount)
	lost := make([]congestion.LostPacketInfo, lossCount)
	b.OnCongestionEventEx(0, monotime.Time(5*time.Second), acked, lost)
	return b.ackRate
}

func TestBrutalLossCompensationDefaultAndOptOut(t *testing.T) {
	tests := []struct {
		name      string
		ack, loss int
		want      float64
	}{
		{name: "no loss", ack: 100, want: 1},
		{name: "twenty percent loss", ack: 80, loss: 20, want: 0.8},
		{name: "loss clamps to floor", ack: 50, loss: 50, want: minAckRate},
		{name: "few samples", ack: 10, loss: 5, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := feedAckRate(false, test.ack, test.loss); got != test.want {
				t.Fatalf("default compensation ack rate = %v, want %v", got, test.want)
			}
			if got := feedAckRate(true, test.ack, test.loss); got != 1 {
				t.Fatalf("disabled compensation ack rate = %v, want 1", got)
			}
		})
	}
}

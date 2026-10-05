package splithttp

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestFlowPingIsRandom(t *testing.T) {
	c := &flowConn{}
	seen := map[uint64]bool{}
	for range 64 {
		frame := c.appendPingFrame(nil)
		if len(frame) != 17 || frame[3] != h2Ping || frame[4] != 0 {
			t.Fatalf("not a PING frame: %x", frame)
		}
		payload := binary.BigEndian.Uint64(frame[9:])
		if seen[payload] {
			t.Fatalf("PING payload %x repeated", payload)
		}
		seen[payload] = true
	}

	c.pingSentAt = time.Now()
	ack := h2Frame{typ: h2Ping, flags: h2FlagAck}
	other := binary.BigEndian.AppendUint64(nil, c.pingData+1)
	if c.pingAck(ack, other) {
		t.Fatal("took the ACK of someone else's PING for ours")
	}
	if !c.pingAck(ack, binary.BigEndian.AppendUint64(nil, c.pingData)) {
		t.Fatal("did not recognize the ACK of our PING")
	}
}

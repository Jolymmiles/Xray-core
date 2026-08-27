package xdns

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// hostileRDLengthMessage builds a decoded request claiming 0xFFFF rdata
// octets while carrying none of them.
func hostileRDLengthMessage(t *testing.T) []byte {
	t.Helper()
	name, err := NewName([][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{
		ID:       1,
		Flags:    0x8000,
		Question: []Question{{Name: name, Type: RRTypeTXT, Class: ClassIN}},
		Answer:   []RR{{Name: name, Type: RRTypeTXT, Class: ClassIN, TTL: 0, Data: []byte{}}},
	}
	buf, err := msg.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(buf[len(buf)-2:], 0xffff)
	return buf
}

// TestDecodeRDLengthBoundedAlloc proves parsing a message whose RDLENGTH
// exceeds the remaining input no longer allocates attacker-sized slices
// before validating them. The budget is measured, not assumed: pre-fix runs
// churn ~65KB per parse.
func TestDecodeRDLengthBoundedAlloc(t *testing.T) {
	buf := hostileRDLengthMessage(t)

	_, err := MessageFromWireFormat(buf)
	if err == nil {
		t.Fatal("expected rejection")
	}

	const iterations = 300
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < iterations; i++ {
		if _, err := MessageFromWireFormat(buf); err == nil {
			t.Fatal("expected rejection mid-loop")
		}
	}
	runtime.ReadMemStats(&after)
	perParse := (after.TotalAlloc - before.TotalAlloc) / iterations
	if perParse > 2048 {
		t.Fatalf("hostile RDLENGTH churns %d B per parse, want <= 2048", perParse)
	}
	t.Logf("per-parse allocation: %d B", perParse)
}

package stun

import "testing"

// attributes turns down a run shorter than an attribute header. The length
// check in message keeps such a run out of SniffSTUN; this keeps attributes
// safe on its own.
func TestAttributesShorterThanAHeader(t *testing.T) {
	for _, b := range [][]byte{{0x80}, {0x80, 0x22}, {0x80, 0x22, 0x00}} {
		if attributes(b) {
			t.Errorf("% x taken for attributes", b)
		}
	}
}

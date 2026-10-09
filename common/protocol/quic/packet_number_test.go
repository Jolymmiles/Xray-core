package quic

import "testing"

// decodePacketNumber follows RFC 9000, Appendix A.3, including its example,
// and recovers numbers across the window in both directions.
func TestDecodePacketNumber(t *testing.T) {
	for _, tt := range []struct {
		largest   int64
		truncated uint64
		length    int
		want      uint64
	}{
		{0xa82f30ea, 0x9b32, 2, 0xa82f9b32}, // the example of Appendix A.3
		{-1, 0, 4, 0},
		{-1, 0xff, 1, 0xff},
		{255, 0x00, 1, 256},
		{300, 0x2c, 1, 300},
		{511, 0xff, 1, 511},
		{256, 0xff, 1, 255},
		{1000, 0x10, 1, 1040},
		{0xffff, 0x0000, 2, 0x10000},
		{5, 3, 4, 3},
	} {
		if got := decodePacketNumber(tt.largest, tt.truncated, tt.length); got != tt.want {
			t.Errorf("decodePacketNumber(%#x, %#x, %d) = %#x, want %#x", tt.largest, tt.truncated, tt.length, got, tt.want)
		}
	}
}

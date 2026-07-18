package hysteria

import "testing"

var paddingBenchmarkSink byte

func TestPaddingFillUsesProtocolAlphabet(t *testing.T) {
	payload := make([]byte, 8192)
	TcpResponsePadding.Fill(payload)
	for index, value := range payload {
		if !containsPaddingByte(value) {
			t.Fatalf("padding[%d] = %q, not in protocol alphabet", index, value)
		}
	}
}

func TestPaddingLenAndStateBoundsAndAlphabet(t *testing.T) {
	for range 1000 {
		length, state := TcpResponsePadding.LenAndState()
		if length < TcpResponsePadding.Min || length >= TcpResponsePadding.Max {
			t.Fatalf("padding length = %d, want [%d,%d)", length, TcpResponsePadding.Min, TcpResponsePadding.Max)
		}
		payload := make([]byte, length)
		TcpResponsePadding.FillWithState(payload, state)
		for index, value := range payload {
			if !containsPaddingByte(value) {
				t.Fatalf("padding[%d] = %q, not in protocol alphabet", index, value)
			}
		}
	}
}

func containsPaddingByte(value byte) bool {
	for index := range len(paddingChars) {
		if paddingChars[index] == value {
			return true
		}
	}
	return false
}

func TestFillPaddingValueProducesTenBase62Digits(t *testing.T) {
	payload := make([]byte, 12)
	written := fillPaddingValue(payload, 1)
	if written != 10 {
		t.Fatalf("written = %d, want 10", written)
	}
	if got, want := string(payload[:written]), "baaaaaaaaa"; got != want {
		t.Fatalf("padding chunk = %q, want %q", got, want)
	}
}

func TestFillPaddingValueMapsExtraChunksIntoAlphabet(t *testing.T) {
	payload := make([]byte, 10)
	written := fillPaddingValue(payload, 62|(1<<6))
	if written != 10 {
		t.Fatalf("written = %d, want 10", written)
	}
	if got, want := string(payload[:written]), "abaaaaaaaa"; got != want {
		t.Fatalf("padding chunk = %q, want %q", got, want)
	}
}

func TestFillPaddingValueFullMapsExtraChunksIntoAlphabet(t *testing.T) {
	var payload [10]byte
	written := fillPaddingValueFull(&payload, 62|(1<<6))
	if written != 10 {
		t.Fatalf("written = %d, want 10", written)
	}
	if got, want := string(payload[:written]), "abaaaaaaaa"; got != want {
		t.Fatalf("padding chunk = %q, want %q", got, want)
	}
}

func BenchmarkPaddingFill512(b *testing.B) {
	payload := make([]byte, 512)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		TcpResponsePadding.Fill(payload)
		paddingBenchmarkSink = payload[len(payload)-1]
	}
}

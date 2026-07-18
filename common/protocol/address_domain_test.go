package protocol

import "testing"

func TestIsValidDomainByteSet(t *testing.T) {
	for value := 0; value < 256; value++ {
		c := byte(value)
		want := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_'
		if got := isValidDomain(string([]byte{c})); got != want {
			t.Fatalf("isValidDomain(%d) = %v, want %v", value, got, want)
		}
	}
}

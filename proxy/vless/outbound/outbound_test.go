package outbound

import (
	"testing"
)

func TestShouldUseTestpreForOrdinaryCarrier(t *testing.T) {
	tests := []struct {
		name    string
		brutal  bool
		testpre uint32
		want    bool
	}{
		{name: "ordinary", testpre: 1, want: true},
		{name: "disabled", want: false},
		{name: "brutal", brutal: true, testpre: 1, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldUseTestpre(test.brutal, test.testpre, nil); got != test.want {
				t.Fatalf("shouldUseTestpre(%t, %d, nil) = %t, want %t", test.brutal, test.testpre, got, test.want)
			}
		})
	}
}

package tcp

import (
	"sync/atomic"
	"testing"

	corelog "github.com/xtls/xray-core/common/log"
)

type countingRealityError struct {
	calls atomic.Int64
}

func (e *countingRealityError) Error() string {
	e.calls.Add(1)
	return "reality handshake rejected"
}

func TestDisabledRealityHandshakeLogDoesNotFormatError(t *testing.T) {
	corelog.RegisterHandler(warningDiscardLogHandler{})
	err := new(countingRealityError)
	logRealityHandshakeError(err)
	if calls := err.calls.Load(); calls != 0 {
		t.Fatalf("Error called %d times, want 0", calls)
	}
}

func BenchmarkDisabledRealityHandshakeLog(b *testing.B) {
	corelog.RegisterHandler(warningDiscardLogHandler{})
	err := new(countingRealityError)
	b.ReportAllocs()
	for b.Loop() {
		logRealityHandshakeError(err)
	}
}

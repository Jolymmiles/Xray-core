package splithttp

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestFlowCodeRabbitUplinkLeak (added for bdbac60e) checks CodeRabbit comment
// 4199461853: whether TestFlowSlowUplinkHandlerBounded leaves HTTP/2 client
// goroutines behind while it runs and after its cleanup.
func TestFlowCodeRabbitUplinkLeak(t *testing.T) {
	count := func() int {
		buf := make([]byte, 1<<22)
		stacks := string(buf[:runtime.Stack(buf, true)])
		return strings.Count(stacks, "readLoop")
	}
	before := count()
	t.Run("inner", TestFlowSlowUplinkHandlerBounded)
	deadline := time.Now().Add(2 * time.Second)
	for count() > before && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("client readLoop goroutines: before %d, after the test's cleanup %d", before, count())
	if count() > before {
		t.Fatalf("%d client readLoop goroutines outlive the test", count()-before)
	}
}

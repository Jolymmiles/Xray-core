package splithttp

import (
	"testing"
	"time"
)

// TestFlowRebasePing has PINGs at 20 ms, then the path move to 80 ms, as a
// client without the kernel's view sees a WiFi to cellular move: once the
// least PING over a window stands there, the queue is counted from it, and
// once the path is back it is counted from 20 ms again. A queue that drains
// now and then, as an own queue under the cuts does, is no move.
func TestFlowRebasePing(t *testing.T) {
	c := &flowConn{}
	now := time.Unix(1, 0)
	feed := func(d time.Duration, rtts ...time.Duration) {
		for end, i := now.Add(d), 0; now.Before(end); now, i = now.Add(time.Second), i+1 {
			c.sampleRTT(now, rtts[i%len(rtts)])
		}
	}
	feed(5*time.Second, 20*time.Millisecond)
	feed(5*time.Second, 80*time.Millisecond)
	if got := c.pingFloor(now); got != 20*time.Millisecond {
		t.Fatalf("five seconds after the move the floor is %v, want 20ms still", got)
	}
	feed(2*flowRTTWindow, 80*time.Millisecond)
	if got := c.pingFloor(now); got != 80*time.Millisecond {
		t.Fatalf("after the path moved to 80ms the floor is %v", got)
	}
	feed(2*flowRTTWindow+time.Second, 20*time.Millisecond)
	if got := c.pingFloor(now); got != 20*time.Millisecond {
		t.Fatalf("the path came back and the floor is %v", got)
	}

	c = &flowConn{}
	feed(5*time.Second, 20*time.Millisecond)
	feed(3*flowRTTWindow, 90*time.Millisecond, 120*time.Millisecond, 25*time.Millisecond)
	if got := c.pingFloor(now); got != 20*time.Millisecond {
		t.Fatalf("a queue that drains every few seconds moved the floor to %v", got)
	}
}

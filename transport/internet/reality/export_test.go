package reality

import (
	"testing"
	"time"
)

// SetSpiderLease makes the spiders started during t keep their connection
// for lease.
func SetSpiderLease(t testing.TB, lease time.Duration) {
	previous := spiderLease
	spiderLease = func() time.Duration { return lease }
	t.Cleanup(func() { spiderLease = previous })
}

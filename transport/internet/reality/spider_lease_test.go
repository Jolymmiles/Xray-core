package reality

import (
	"testing"
	"time"
)

// The lease outlasts the idle timeouts servers apply to HTTP/2 connections by
// default (nginx 75 s, Cloudflare 400 s, Google Cloud load balancers 610 s),
// so with them the server closes the spider's connection first.
func TestSpiderLeaseOutlastsServerIdleTimeouts(t *testing.T) {
	for range 1000 {
		if lease := spiderLease(); lease < 660*time.Second || lease >= 720*time.Second {
			t.Fatalf("lease %v outside [660 s, 720 s)", lease)
		}
	}
}

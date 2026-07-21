//go:build integration

package singmux_test

type processResourceSnapshot struct {
	rssKiB  uint64
	threads uint64
	fds     uint64
}

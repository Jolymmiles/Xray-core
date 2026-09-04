//go:build integration && stress && performance

package singmux_test

import (
	"sort"
	"time"
)

const performanceRounds = 9

func medianDuration(samples []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	return sorted[len(sorted)/2]
}

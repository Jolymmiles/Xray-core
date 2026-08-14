package presence

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestSevenThousandExactOwnersEndAtZero(t *testing.T) {
	const email = "aggregate-soak@example.com"
	fixture := New(t)
	owners := make([]session.PresenceLease, 7000)
	for index := range owners {
		ip := fmt.Sprintf("198.51.%d.%d", index/254, index%254+1)
		owners[index] = fixture.Scope(t, email, ip).Prepare().Activate()
	}
	fixture.AssertIPCount(t, email, len(owners))
	for _, owner := range owners {
		owner.Close()
	}
	fixture.AssertIPCount(t, email, 0)
	fixture.AssertIPs(t, email)
}

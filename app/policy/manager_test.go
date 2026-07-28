package policy_test

import (
	"context"
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

func TestPolicy(t *testing.T) {
	manager, err := New(context.Background(), &Config{
		Level: map[uint32]*Policy{
			0: {
				Timeout: &Policy_Timeout{
					Handshake: &Second{
						Value: 2,
					},
				},
			},
		},
	})
	common.Must(err)

	pDefault := policy.SessionDefault()

	{
		p := manager.ForLevel(0)
		if p.Timeouts.Handshake != 2*time.Second {
			t.Error("expect 2 sec timeout, but got ", p.Timeouts.Handshake)
		}
		if p.Timeouts.ConnectionIdle != pDefault.Timeouts.ConnectionIdle {
			t.Error("expect ", pDefault.Timeouts.ConnectionIdle, " sec timeout, but got ", p.Timeouts.ConnectionIdle)
		}
	}

	{
		p := manager.ForLevel(1)
		if p.Timeouts.Handshake != pDefault.Timeouts.Handshake {
			t.Error("expect ", pDefault.Timeouts.Handshake, " sec timeout, but got ", p.Timeouts.Handshake)
		}
	}
}

// MaxConnectionIdle must surface the highest configured connIdle so route-
// independent consumers (SMUX carrier idle) can bound against Freedom's
// userLevel without knowing the outbound in advance.
func TestMaxConnectionIdle(t *testing.T) {
	manager, err := New(context.Background(), &Config{
		Level: map[uint32]*Policy{
			0: {
				Timeout: &Policy_Timeout{
					ConnectionIdle: &Second{Value: 300},
				},
			},
			7: {
				Timeout: &Policy_Timeout{
					ConnectionIdle: &Second{Value: 3600},
				},
			},
		},
	})
	common.Must(err)

	if got := manager.MaxConnectionIdle(); got != 3600*time.Second {
		t.Fatalf("MaxConnectionIdle = %v, want 3600s", got)
	}
}

// With no explicit levels the max is SessionDefault, matching ForLevel on any
// unconfigured index.
func TestMaxConnectionIdleDefaultOnly(t *testing.T) {
	manager, err := New(context.Background(), &Config{})
	common.Must(err)

	want := policy.SessionDefault().Timeouts.ConnectionIdle
	if got := manager.MaxConnectionIdle(); got != want {
		t.Fatalf("MaxConnectionIdle with empty config = %v, want %v", got, want)
	}
}

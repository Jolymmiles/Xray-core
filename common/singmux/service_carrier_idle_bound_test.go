// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
)

// asymmetricPolicyManager models the documented residual: inbound users sit at
// level 0 with connIdle 300s, while Freedom (or any outbound with its own
// userLevel) runs at level 7 with connIdle 3600s. Deriving the carrier window
// from the inbound level alone reaps a quiet live stream at 600s.
//
// MaxConnectionIdle mirrors app/policy.Instance so the production path is what
// this fixture exercises.
type asymmetricPolicyManager struct {
	policy.Manager
	// levels maps user level → ConnectionIdle. Missing levels fall through to
	// SessionDefault, matching app/policy.Instance.
	levels map[uint32]time.Duration
}

func (m *asymmetricPolicyManager) ForLevel(level uint32) policy.Session {
	result := policy.SessionDefault()
	if idle, ok := m.levels[level]; ok {
		result.Timeouts.ConnectionIdle = idle
	}
	return result
}

func (m *asymmetricPolicyManager) MaxConnectionIdle() time.Duration {
	maxIdle := policy.SessionDefault().Timeouts.ConnectionIdle
	for _, idle := range m.levels {
		if idle > maxIdle {
			maxIdle = idle
		}
	}
	return maxIdle
}

// The swarm residual: inbound connIdle 300s, outbound level-7 connIdle 3600s.
// After the fix the carrier window must be at least 2× the largest configured
// connIdle (7200s), not 2× the inbound level alone (600s).
func TestCarrierIdleTimeoutCoversOutboundPolicyLevel(t *testing.T) {
	const (
		inboundIdle  = 300 * time.Second
		outboundIdle = 3600 * time.Second
	)

	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	// Floor at the stock default so a buggy inbound-only derivation would
	// return max(default, 2×300s) = 600s and miss the outbound intent.
	service.carrierIdleTimeout = defaultCarrierIdleTimeout
	service.SetPolicy(&asymmetricPolicyManager{
		levels: map[uint32]time.Duration{
			0: inboundIdle,
			7: outboundIdle,
		},
	})

	// Carrier arrives as the inbound user (level 0). Outbound Freedom will
	// later arm its stream timer from level 7 — that level is not on ctx.
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Level: 0},
	})

	got := service.carrierIdleTimeoutFor(ctx)
	want := 2 * outboundIdle
	if got < want {
		t.Fatalf("carrierIdleTimeoutFor with inbound level 0 and level-7 connIdle %v = %v, want >= %v (2× max policy connIdle); inbound-only derivation undercuts the outbound stream timer",
			outboundIdle, got, want)
	}
}

// Probing must not require MaxConnectionIdle: features/policy.DefaultManager
// and other ForLevel-only managers still have to raise the carrier window for
// the highest connIdle in the probe range so the reaper stays policy-aware.
func TestCarrierIdleTimeoutProbesPolicyLevelsWithoutMaxAccessor(t *testing.T) {
	const outboundIdle = 3600 * time.Second

	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.carrierIdleTimeout = defaultCarrierIdleTimeout
	// Deliberately omit MaxConnectionIdle — only ForLevel is available.
	service.SetPolicy(&probeOnlyPolicyManager{
		levels: map[uint32]time.Duration{
			0: 300 * time.Second,
			7: outboundIdle,
		},
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User: &protocol.MemoryUser{Level: 0},
	})
	got := service.carrierIdleTimeoutFor(ctx)
	want := 2 * outboundIdle
	if got < want {
		t.Fatalf("carrierIdleTimeoutFor without MaxConnectionIdle = %v, want >= %v", got, want)
	}
}

// probeOnlyPolicyManager is policy.Manager without MaxConnectionIdle.
type probeOnlyPolicyManager struct {
	policy.Manager
	levels map[uint32]time.Duration
}

func (m *probeOnlyPolicyManager) ForLevel(level uint32) policy.Session {
	result := policy.SessionDefault()
	if idle, ok := m.levels[level]; ok {
		result.Timeouts.ConnectionIdle = idle
	}
	return result
}

// A disabled watchdog stays disabled even when policy levels would raise it.
func TestCarrierIdleTimeoutStaysDisabledWithAsymmetricPolicy(t *testing.T) {
	service := NewService(&detachedDispatcher{started: make(chan struct{}, 1)})
	service.carrierIdleTimeout = 0
	service.SetPolicy(&asymmetricPolicyManager{
		levels: map[uint32]time.Duration{7: time.Hour},
	})
	if got := service.carrierIdleTimeoutFor(context.Background()); got != 0 {
		t.Fatalf("carrierIdleTimeoutFor with watchdog disabled = %v, want 0", got)
	}
}

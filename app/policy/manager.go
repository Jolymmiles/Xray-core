package policy

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

// Instance is an instance of Policy manager.
type Instance struct {
	levels map[uint32]*Policy
	system *SystemPolicy
}

// New creates new Policy manager instance.
func New(ctx context.Context, config *Config) (*Instance, error) {
	m := &Instance{
		levels: make(map[uint32]*Policy),
		system: config.System,
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
		}
	}

	return m, nil
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

// ForLevel implements policy.Manager.
func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.levels[level]; ok {
		return p.ToCorePolicy()
	}
	return policy.SessionDefault()
}

// MaxConnectionIdle returns the largest ConnectionIdle among SessionDefault and
// every explicitly configured user level. Levels absent from the map fall
// through to SessionDefault on ForLevel, so they cannot exceed this value.
//
// Callers that need a route-independent upper bound (for example SMUX carrier
// idle reaping, where Freedom may arm connIdle from its own userLevel) should
// use this instead of ForLevel on the inbound user alone.
func (m *Instance) MaxConnectionIdle() time.Duration {
	maxIdle := policy.SessionDefault().Timeouts.ConnectionIdle
	for _, p := range m.levels {
		if p == nil {
			continue
		}
		if idle := p.ToCorePolicy().Timeouts.ConnectionIdle; idle > maxIdle {
			maxIdle = idle
		}
	}
	return maxIdle
}

// ForSystem implements policy.Manager.
func (m *Instance) ForSystem() policy.System {
	if m.system == nil {
		return policy.System{}
	}
	return m.system.ToCorePolicy()
}

// Start implements common.Runnable.Start().
func (m *Instance) Start() error {
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

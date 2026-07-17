package outbound

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

// Manager is to manage all outbound handlers.
type Manager struct {
	access           sync.RWMutex
	defaultHandler   outbound.Handler
	taggedHandler    map[string]outbound.Handler
	untaggedHandlers []outbound.Handler
	running          bool
	tagsCache        atomic.Pointer[sync.Map]
	lookup           atomic.Pointer[handlerSnapshot]
}

type handlerSnapshot struct {
	defaultHandler outbound.Handler
	taggedHandler  map[string]outbound.Handler
}

// New creates a new Manager.
func New(ctx context.Context, config *proxyman.OutboundConfig) (*Manager, error) {
	m := &Manager{taggedHandler: make(map[string]outbound.Handler)}
	m.tagsCache.Store(&sync.Map{})
	m.publishSnapshotLocked()
	return m, nil
}

func (m *Manager) publishSnapshotLocked() {
	taggedHandler := make(map[string]outbound.Handler, len(m.taggedHandler))
	for tag, handler := range m.taggedHandler {
		taggedHandler[tag] = handler
	}
	m.lookup.Store(&handlerSnapshot{
		defaultHandler: m.defaultHandler,
		taggedHandler:  taggedHandler,
	})
}

// Type implements common.HasType.
func (m *Manager) Type() interface{} {
	return outbound.ManagerType()
}

// Start implements core.Feature
func (m *Manager) Start() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = true

	for _, h := range m.taggedHandler {
		if err := h.Start(); err != nil {
			return err
		}
	}

	for _, h := range m.untaggedHandlers {
		if err := h.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Close implements core.Feature
func (m *Manager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = false

	var errs []error
	for _, h := range m.taggedHandler {
		errs = append(errs, h.Close())
	}

	for _, h := range m.untaggedHandlers {
		errs = append(errs, h.Close())
	}

	return errors.Combine(errs...)
}

// GetDefaultHandler implements outbound.Manager.
func (m *Manager) GetDefaultHandler() outbound.Handler {
	snapshot := m.lookup.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot.defaultHandler
}

// GetHandler implements outbound.Manager.
func (m *Manager) GetHandler(tag string) outbound.Handler {
	snapshot := m.lookup.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot.taggedHandler[tag]
}

// AddHandler implements outbound.Manager.
func (m *Manager) AddHandler(ctx context.Context, handler outbound.Handler) error {
	m.access.Lock()
	defer m.access.Unlock()
	defer m.publishSnapshotLocked()

	m.tagsCache.Store(&sync.Map{})

	if m.defaultHandler == nil {
		m.defaultHandler = handler
	}

	tag := handler.Tag()
	if len(tag) > 0 {
		if _, found := m.taggedHandler[tag]; found {
			return errors.New("existing tag found: " + tag)
		}
		m.taggedHandler[tag] = handler
	} else {
		m.untaggedHandlers = append(m.untaggedHandlers, handler)
	}

	if m.running {
		return handler.Start()
	}

	return nil
}

// RemoveHandler implements outbound.Manager.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}
	m.access.Lock()
	defer m.access.Unlock()
	defer m.publishSnapshotLocked()

	m.tagsCache.Store(&sync.Map{})

	delete(m.taggedHandler, tag)
	if m.defaultHandler != nil && m.defaultHandler.Tag() == tag {
		m.defaultHandler = nil
	}

	return nil
}

// ListHandlers implements outbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []outbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	response := make([]outbound.Handler, len(m.untaggedHandlers))
	copy(response, m.untaggedHandlers)

	for _, v := range m.taggedHandler {
		response = append(response, v)
	}

	return response
}

// Select implements outbound.HandlerSelector.
func (m *Manager) Select(selectors []string) []string {
	key := strings.Join(selectors, ",")
	if cache := m.tagsCache.Load(); cache != nil {
		if tags, ok := cache.Load(key); ok {
			return tags.([]string)
		}
	}

	m.access.RLock()
	defer m.access.RUnlock()
	cache := m.tagsCache.Load()
	if cache != nil {
		if tags, ok := cache.Load(key); ok {
			return tags.([]string)
		}
	}

	tags := make([]string, 0, len(selectors))

	for tag := range m.taggedHandler {
		for _, selector := range selectors {
			if strings.HasPrefix(tag, selector) {
				tags = append(tags, tag)
				break
			}
		}
	}

	sort.Strings(tags)
	if cache != nil {
		cache.Store(key, tags)
	}

	return tags
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.OutboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.OutboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.OutboundHandlerConfig))
	}))
}

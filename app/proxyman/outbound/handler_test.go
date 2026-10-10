package outbound_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestInterfaces(t *testing.T) {
	_ = outbound.Handler(new(Handler))
	_ = outbound.Manager(new(Manager))
}

const xrayKey core.XrayKey = 1

func TestOutboundWithoutStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						InboundUplink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if ok {
		t.Errorf("Expected conn to not be CounterConnection")
	}
}

func TestOutboundWithStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if !ok {
		t.Errorf("Expected conn to be CounterConnection")
	}
}

func TestTagsCache(t *testing.T) {
	test_duration := 10 * time.Second
	threads_num := 50
	delay := 10 * time.Millisecond
	tags_prefix := "node"

	tags := sync.Map{}
	counter := atomic.Uint64{}

	ohm, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Error("failed to create outbound handler manager")
	}
	config := &core.Config{
		App: []*serial.TypedMessage{},
	}
	v, _ := core.New(config)
	v.AddFeature(ohm)
	ctx := context.WithValue(context.Background(), xrayKey, v)

	stopAddRemove := atomic.Bool{}
	wg_add_rm := sync.WaitGroup{}
	addHandlers := func() {
		defer wg_add_rm.Done()
		for !stopAddRemove.Load() {
			time.Sleep(delay)
			idx := counter.Add(1)
			tag := fmt.Sprintf("%s%d", tags_prefix, idx)
			cfg := &core.OutboundHandlerConfig{
				Tag:           tag,
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
			}
			if h, err := NewHandler(ctx, cfg); err == nil {
				if err := ohm.AddHandler(ctx, h); err == nil {
					// t.Log("add handler:", tag)
					tags.Store(tag, nil)
				} else {
					t.Error("failed to add handler:", tag)
				}
			} else {
				t.Error("failed to create handler:", tag)
			}
		}
	}

	rmHandlers := func() {
		defer wg_add_rm.Done()
		for !stopAddRemove.Load() {
			time.Sleep(delay)
			tags.Range(func(key interface{}, value interface{}) bool {
				if _, ok := tags.LoadAndDelete(key); ok {
					// t.Log("remove handler:", key)
					ohm.RemoveHandler(ctx, key.(string))
					return false
				}
				return true
			})
		}
	}

	selectors := []string{tags_prefix}
	wg_get := sync.WaitGroup{}
	stopGet := atomic.Bool{}
	getTags := func() {
		defer wg_get.Done()
		for !stopGet.Load() {
			time.Sleep(delay)
			_ = ohm.Select(selectors)
			// t.Logf("get tags: %v", tag)
		}
	}

	for i := 0; i < threads_num; i++ {
		wg_add_rm.Add(2)
		go rmHandlers()
		go addHandlers()
		wg_get.Add(1)
		go getTags()
	}

	time.Sleep(test_duration)
	stopAddRemove.Store(true)
	wg_add_rm.Wait()
	stopGet.Store(true)
	wg_get.Wait()
}

type closeCountingHandler struct {
	tag     string
	closed  atomic.Int32
	onClose func()
}

func (h *closeCountingHandler) Start() error { return nil }

func (h *closeCountingHandler) Close() error {
	h.closed.Add(1)
	if h.onClose != nil {
		h.onClose()
	}
	return nil
}

func (h *closeCountingHandler) Tag() string                               { return h.tag }
func (h *closeCountingHandler) Dispatch(context.Context, *transport.Link) {}
func (h *closeCountingHandler) SenderSettings() *serial.TypedMessage      { return nil }
func (h *closeCountingHandler) ProxySettings() *serial.TypedMessage       { return nil }

// HandlerService.RemoveOutbound removes through RemoveHandler; whatever the
// removed handler's Close releases (a WireGuard TUN, a VLESS reverse that
// redials every 2 s) must not outlive the removal.
func TestRemoveHandlerClosesHandler(t *testing.T) {
	ctx := context.Background()
	ohm, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ohm.Start(); err != nil {
		t.Fatal(err)
	}
	kept := &closeCountingHandler{tag: "kept"}
	removed := &closeCountingHandler{tag: "removed"}
	for _, h := range []*closeCountingHandler{kept, removed} {
		if err := ohm.AddHandler(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	if err := ohm.RemoveHandler(ctx, "removed"); err != nil {
		t.Fatal(err)
	}
	if ohm.GetHandler("removed") != nil {
		t.Fatal("the removed handler is still published")
	}
	if n := removed.closed.Load(); n != 1 {
		t.Fatalf("the removed handler was closed %d times, want 1", n)
	}
	if n := kept.closed.Load(); n != 0 {
		t.Fatalf("removing another tag closed the kept handler %d times", n)
	}

	// Neither removing it again, removing an unknown tag, nor closing the
	// manager closes it again.
	for _, tag := range []string{"removed", "unknown"} {
		if err := ohm.RemoveHandler(ctx, tag); err != nil {
			t.Fatalf("RemoveHandler(%q) = %v, want nil", tag, err)
		}
	}
	if err := ohm.Close(); err != nil {
		t.Fatal(err)
	}
	if n := removed.closed.Load(); n != 1 {
		t.Fatalf("the removed handler was closed %d times in total, want 1", n)
	}
	if n := kept.closed.Load(); n != 1 {
		t.Fatalf("closing the manager closed the kept handler %d times, want 1", n)
	}
}

// A removed handler's Close can be slow (WireGuard tears its device down, a
// VLESS reverse waits for its bridges). It runs after the handler is
// unpublished and without the manager lock, so selecting and adding handlers
// proceed meanwhile.
func TestRemoveHandlerClosesAfterUnpublishingWithoutTheLock(t *testing.T) {
	ctx := context.Background()
	ohm, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	removed := &closeCountingHandler{tag: "removed"}
	if err := ohm.AddHandler(ctx, removed); err != nil {
		t.Fatal(err)
	}
	var published, defaultHandler outbound.Handler
	var selected []string
	var addErr error
	removed.onClose = func() {
		published = ohm.GetHandler("removed")
		defaultHandler = ohm.GetDefaultHandler()
		selected = ohm.Select([]string{"rem"})
		addErr = ohm.AddHandler(ctx, &closeCountingHandler{tag: "added-during-close"})
	}

	done := make(chan error, 1)
	go func() { done <- ohm.RemoveHandler(ctx, "removed") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RemoveHandler did not return: the removed handler's Close waited for the manager lock")
	}

	if n := removed.closed.Load(); n != 1 {
		t.Fatalf("the removed handler was closed %d times, want 1", n)
	}
	if published != nil || defaultHandler != nil {
		t.Fatalf("Close ran while the removed handler was still published: GetHandler=%v, GetDefaultHandler=%v", published, defaultHandler)
	}
	if len(selected) != 0 {
		t.Fatalf("Close ran while Select still returned the removed tag: %v", selected)
	}
	if addErr != nil {
		t.Fatalf("AddHandler during the removed handler's Close: %v", addErr)
	}
	if ohm.GetHandler("added-during-close") == nil {
		t.Fatal("the handler added during Close is not published")
	}
}

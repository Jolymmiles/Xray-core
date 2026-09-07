package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

	outboundapp "github.com/xtls/xray-core/app/proxyman/outbound"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
)

type cleanupConnection struct {
	net.Conn
	entered chan struct{}
	resume  chan struct{}
	err     error
}

func (c *cleanupConnection) Close() error {
	if c.entered != nil {
		close(c.entered)
		<-c.resume
	}
	return errors.Join(c.Conn.Close(), c.err)
}

func cleanupCarrier(t *testing.T, h *Handler, u *protocol.MemoryUser, blocked bool) (*cleanupConnection, context.Context, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	connection := &cleanupConnection{Conn: server}
	if blocked {
		connection.entered, connection.resume = make(chan struct{}), make(chan struct{})
	}
	ctx, unregister, err := h.registerMuxCarrier(context.Background(), u, connection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unregister(); _ = server.Close(); _ = client.Close() })
	return connection, ctx, client
}

// Detached cleanup must remain an operation-completion barrier in either order.
func TestMUXCleanupCloseRemoveOrdering(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("close-first=%v", closeFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
				h := revocationHandler(t, u)
				connection, ctx, peer := cleanupCarrier(t, h, u, true)
				first, second := make(chan error, 1), make(chan error, 1)
				remove := func() error { return h.RemoveUser(context.Background(), u.Email) }
				if closeFirst {
					go func() { first <- h.Close() }()
				} else {
					go func() { first <- remove() }()
				}
				<-connection.entered
				if closeFirst {
					go func() { second <- remove() }()
				} else {
					go func() { second <- h.Close() }()
				}
				synctest.Wait()
				var early bool
				select {
				case err := <-second:
					early = true
					t.Errorf("second lifecycle operation returned before physical cleanup completed: %v", err)
				default:
				}
				if !h.userMu.TryLock() {
					t.Error("physical Close held userMu")
				} else {
					h.userMu.Unlock()
				}
				close(connection.resume)
				if err := <-first; err != nil {
					t.Fatal(err)
				}
				if !early {
					err := <-second
					if closeFirst && err == nil {
						t.Error("RemoveUser reported success after handler Close admission")
					}
					if !closeFirst && err != nil {
						t.Fatal(err)
					}
				}
				if ctx.Err() != context.Canceled {
					t.Error("carrier context was not canceled")
				}
				var one [1]byte
				if _, err := peer.Read(one[:]); err != io.EOF {
					t.Fatalf("physical carrier remained open: %v", err)
				}
			})
		})
	}
}

type cleanupReverseManager struct {
	outbound.Manager
	lookupEntered, lookupResume chan struct{}
	listEntered, listResume     chan struct{}
	lookupPaused                atomic.Bool
}

func (m *cleanupReverseManager) GetHandler(tag string) outbound.Handler {
	if tag == "reverse" && m.lookupEntered != nil && m.lookupPaused.CompareAndSwap(false, true) {
		close(m.lookupEntered)
		<-m.lookupResume
	}
	return m.Manager.GetHandler(tag)
}

func (m *cleanupReverseManager) ListHandlers(ctx context.Context) []outbound.Handler {
	if m.listEntered != nil {
		close(m.listEntered)
		<-m.listResume
	}
	return m.Manager.ListHandlers(ctx)
}

func cleanupReverseHandler(t *testing.T) (*Handler, *protocol.MemoryUser, *cleanupReverseManager) {
	t.Helper()
	u := revocationUser(t, "reverse@example.com", "00112233-4455-6677-8899-aabbccddeeff")
	u.Account.(*vless.MemoryAccount).Reverse = &vless.Reverse{Tag: "reverse"}
	h := revocationHandler(t, u)
	manager, err := outboundapp.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Only a ready default outbound is needed; the reverse owner is constructed by GetReverse.
	if err := manager.AddHandler(context.Background(), &Reverse{tag: "default"}); err != nil {
		t.Fatal(err)
	}
	wrapped := &cleanupReverseManager{Manager: manager}
	h.outboundHandlerManager = wrapped
	return h, u, wrapped
}

// Re-add must not publish a new tag owner while the old removal can still delete it.
func TestMUXCleanupReverseReAddWaitsForOldRemoval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, u, manager := cleanupReverseHandler(t)
		manager.lookupEntered, manager.lookupResume = make(chan struct{}), make(chan struct{})
		removed := make(chan error, 1)
		go func() { removed <- h.RemoveUser(context.Background(), u.Email) }()
		<-manager.lookupEntered
		type result struct {
			owner *Reverse
			err   error
		}
		added := make(chan result, 1)
		go func() {
			if err := h.AddUser(context.Background(), u); err != nil {
				added <- result{err: err}
				return
			}
			owner, err := h.GetReverse(u.Account.(*vless.MemoryAccount))
			added <- result{owner, err}
		}()
		synctest.Wait()
		var fresh result
		var early bool
		select {
		case fresh = <-added:
			early = true
			t.Error("re-add published its reverse owner before old removal completed")
		default:
		}
		close(manager.lookupResume)
		if err := <-removed; err != nil {
			t.Fatal(err)
		}
		if !early {
			fresh = <-added
		}
		if fresh.err != nil {
			t.Fatal(fresh.err)
		}
		if owner := manager.Manager.GetHandler("reverse"); owner != fresh.owner {
			t.Error("old removal deleted the fresh reverse owner")
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

// Close must not join a reverse call while holding the gate that call needs to reject publication.
func TestMUXCleanupCloseRejectsLateReversePublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, reverseUser, manager := cleanupReverseHandler(t)
		user := revocationUser(t, "mux@example.com", "11112233-4455-6677-8899-aabbccddeeff")
		if err := h.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
		connection, _, _ := cleanupCarrier(t, h, h.GetUser(context.Background(), user.Email), true)
		manager.listEntered, manager.listResume = make(chan struct{}), make(chan struct{})
		reverseDone := make(chan error, 1)
		go func() { _, err := h.GetReverse(reverseUser.Account.(*vless.MemoryAccount)); reverseDone <- err }()
		<-manager.listEntered
		closed := make(chan error, 1)
		go func() { closed <- h.Close() }()
		<-connection.entered
		close(manager.listResume)
		synctest.Wait()
		close(connection.resume)
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := <-reverseDone; err == nil {
			t.Error("reverse owner was published after handler Close began")
		}
		if manager.Manager.GetHandler("reverse") != nil {
			t.Error("closed handler retained a reverse owner")
		}
	})
}

// Readiness must neither block RemoveUser nor revive the identity captured before the wait.
func TestMUXCleanupReverseReadinessRevalidatesUser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, user, manager := cleanupReverseHandler(t)
		manager.listEntered, manager.listResume = make(chan struct{}), make(chan struct{})
		reverseDone := make(chan error, 1)
		go func() { _, err := h.GetReverse(user.Account.(*vless.MemoryAccount)); reverseDone <- err }()
		<-manager.listEntered
		if err := h.RemoveUser(context.Background(), user.Email); err != nil {
			t.Fatal(err)
		}
		if err := h.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
		close(manager.listResume)
		if err := <-reverseDone; err == nil {
			t.Error("reverse readiness wait revived pre-removal authentication")
		}
		if manager.Manager.GetHandler("reverse") != nil {
			t.Error("stale reverse call published an owner")
		}
		manager.listEntered = nil
		if _, err := h.GetReverse(user.Account.(*vless.MemoryAccount)); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMUXCleanupPreservesAbnormalCloseErrors(t *testing.T) {
	// Xray errors implement Unwrap even when they are leaves (nil inner error).
	abnormal := xerrors.New("unexpected cleanup failure")
	for _, closeHandler := range []bool{false, true} {
		for name, closeErr := range map[string]error{
			"joined":        errors.Join(net.ErrClosed, abnormal),
			"wrapped-join":  fmt.Errorf("close transport: %w", errors.Join(io.ErrClosedPipe, abnormal)),
			"only-expected": errors.Join(net.ErrClosed, fmt.Errorf("closed stream: %w", io.ErrClosedPipe)),
		} {
			t.Run(fmt.Sprintf("handler=%v/%s", closeHandler, name), func(t *testing.T) {
				u := revocationUser(t, "removed@example.com", "00112233-4455-6677-8899-aabbccddeeff")
				h := revocationHandler(t, u)
				connection, _, _ := cleanupCarrier(t, h, u, false)
				connection.err = closeErr
				var err error
				if closeHandler {
					err = h.Close()
				} else {
					err = h.RemoveUser(context.Background(), u.Email)
				}
				if name == "only-expected" {
					if err != nil {
						t.Errorf("expected-close leaves were retained: %v", err)
					}
				} else if !errors.Is(err, abnormal) {
					t.Errorf("abnormal cleanup error was lost: %v", err)
				}
				if name == "wrapped-join" && err != nil && !strings.Contains(err.Error(), "close transport:") {
					t.Errorf("transport close context was lost: %v", err)
				}
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("expected-close leaf was not filtered: %v", err)
				}
			})
		}
	}
}

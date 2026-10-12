package proxy

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

type staticUserLookup map[string]*protocol.MemoryUser

func (l staticUserLookup) GetByEmail(email string) *protocol.MemoryUser {
	return l[strings.ToLower(email)]
}

type countingCloser struct {
	closes atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func newCountingCloser() *countingCloser {
	return &countingCloser{closed: make(chan struct{})}
}

func (c *countingCloser) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *countingCloser) waitClosed(t *testing.T, name string) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s was not closed", name)
	}
}

func requireCanceled(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("%s context was not canceled", name)
	}
}

func requireLive(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s context ended: %v", name, err)
	}
}

func TestUserConnectionsRevokeClosesOnlyThatUser(t *testing.T) {
	victim := &protocol.MemoryUser{Email: "Victim@example.com"}
	bystander := &protocol.MemoryUser{Email: "bystander@example.com"}
	users := staticUserLookup{"victim@example.com": victim, "bystander@example.com": bystander}
	var connections UserConnections

	victimConns := []*countingCloser{newCountingCloser(), newCountingCloser()}
	victimContexts := make([]context.Context, len(victimConns))
	for i, conn := range victimConns {
		ctx, tracked, err := connections.Track(context.Background(), users, victim, conn)
		if err != nil {
			t.Fatal(err)
		}
		defer tracked.Release()
		victimContexts[i] = ctx
	}
	bystanderConn := newCountingCloser()
	bystanderCtx, bystanderTracked, err := connections.Track(context.Background(), users, bystander, bystanderConn)
	if err != nil {
		t.Fatal(err)
	}
	defer bystanderTracked.Release()

	delete(users, "victim@example.com")
	connections.Revoke(victim)

	for i, conn := range victimConns {
		name := "victim connection " + strconv.Itoa(i)
		conn.waitClosed(t, name)
		requireCanceled(t, victimContexts[i], name)
	}
	if got := bystanderConn.closes.Load(); got != 0 {
		t.Fatalf("revoking another user closed the bystander connection %d times", got)
	}
	requireLive(t, bystanderCtx, "bystander")
}

func TestUserConnectionsTrackRejectsUserNoLongerCurrent(t *testing.T) {
	removed := &protocol.MemoryUser{Email: "user@example.com"}
	readded := &protocol.MemoryUser{Email: "user@example.com"}
	var connections UserConnections

	for name, users := range map[string]staticUserLookup{
		"removed":  {},
		"re-added": {"user@example.com": readded},
	} {
		t.Run(name, func(t *testing.T) {
			conn := newCountingCloser()
			ctx, tracked, err := connections.Track(context.Background(), users, removed, conn)
			if err == nil {
				tracked.Release()
				t.Fatal("tracked a connection of a user the inbound no longer accepts")
			}
			if ctx != nil || tracked != nil {
				t.Fatalf("rejected Track returned ctx=%v tracked=%v", ctx, tracked)
			}
			connections.Revoke(removed)
			if got := conn.closes.Load(); got != 0 {
				t.Fatalf("a rejected connection was closed %d times by the registry; its owner closes it", got)
			}
		})
	}
}

func TestUserConnectionsIgnoresUsersWithoutEmail(t *testing.T) {
	user := &protocol.MemoryUser{}
	users := staticUserLookup{"": user}
	var connections UserConnections
	parent := context.Background()

	ctx, tracked, err := connections.Track(parent, users, user, newCountingCloser())
	if err != nil {
		t.Fatal(err)
	}
	if ctx != parent || tracked != nil {
		t.Fatalf("a user without an email, which no RemoveUser can name, was tracked: ctx=%v tracked=%v", ctx, tracked)
	}
	tracked.Release()
}

func TestUserConnectionsReleasedConnectionIsNotRevoked(t *testing.T) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	users := staticUserLookup{"user@example.com": user}
	var connections UserConnections
	conn := newCountingCloser()

	ctx, tracked, err := connections.Track(context.Background(), users, user, conn)
	if err != nil {
		t.Fatal(err)
	}
	tracked.Release()
	requireCanceled(t, ctx, "released connection")
	connections.Revoke(user)
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("a released connection was closed %d times by Revoke", got)
	}
	tracked.Release()
}

func TestUserConnectionsReleaseAfterRevokeClosesOnce(t *testing.T) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	users := staticUserLookup{"user@example.com": user}
	var connections UserConnections
	conn := newCountingCloser()

	_, tracked, err := connections.Track(context.Background(), users, user, conn)
	if err != nil {
		t.Fatal(err)
	}
	connections.Revoke(user)
	conn.waitClosed(t, "revoked connection")
	tracked.Release()
	connections.Revoke(user)
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("revoked connection closed %d times by the registry, want 1", got)
	}
}

type blockingCloser struct {
	entered chan struct{}
	release chan struct{}
}

func (c *blockingCloser) Close() error {
	close(c.entered)
	<-c.release
	return nil
}

func TestUserConnectionsRevokeDoesNotWaitForClose(t *testing.T) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	users := staticUserLookup{"user@example.com": user}
	var connections UserConnections
	stuck := &blockingCloser{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(stuck.release) })

	ctx, tracked, err := connections.Track(context.Background(), users, user, stuck)
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Release()

	revoked := make(chan struct{})
	go func() {
		connections.Revoke(user)
		close(revoked)
	}()
	select {
	case <-revoked:
	case <-time.After(5 * time.Second):
		t.Fatal("Revoke waited for a connection whose Close does not return")
	}
	requireCanceled(t, ctx, "connection with a stuck Close")
	select {
	case <-stuck.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Revoke did not start closing the connection")
	}
}

func TestUserConnectionsConcurrentTrackReleaseRevoke(t *testing.T) {
	const workers = 8
	const rounds = 200
	user := &protocol.MemoryUser{Email: "user@example.com"}
	users := staticUserLookup{"user@example.com": user}
	var connections UserConnections

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				conn := newCountingCloser()
				_, tracked, err := connections.Track(context.Background(), users, user, conn)
				if err != nil {
					t.Error(err)
					return
				}
				tracked.Release()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range rounds {
			connections.Revoke(user)
		}
	}()
	wg.Wait()

	connections.mu.Lock()
	defer connections.mu.Unlock()
	if len(connections.users) != 0 {
		t.Fatalf("registry kept %d users after every connection was released", len(connections.users))
	}
}

func BenchmarkUserConnectionsTrackRelease(b *testing.B) {
	for _, userCount := range []int{1, 10000} {
		b.Run("users="+strconv.Itoa(userCount), func(b *testing.B) {
			users := make(staticUserLookup, userCount)
			members := make([]*protocol.MemoryUser, userCount)
			for i := range members {
				email := "user" + strconv.Itoa(i) + "@example.com"
				members[i] = &protocol.MemoryUser{Email: email}
				users[email] = members[i]
			}
			var connections UserConnections
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := newCountingCloser()
			b.ReportAllocs()
			b.ResetTimer()
			i := 0
			for b.Loop() {
				_, tracked, err := connections.Track(parent, users, members[i%userCount], conn)
				if err != nil {
					b.Fatal(err)
				}
				tracked.Release()
				i++
			}
		})
	}
}

func BenchmarkUserConnectionsTrackReleaseParallel(b *testing.B) {
	const userCount = 1024
	users := make(staticUserLookup, userCount)
	members := make([]*protocol.MemoryUser, userCount)
	for i := range members {
		email := "user" + strconv.Itoa(i) + "@example.com"
		members[i] = &protocol.MemoryUser{Email: email}
		users[email] = members[i]
	}
	var connections UserConnections
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	var next atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		conn := newCountingCloser()
		user := members[next.Add(1)%userCount]
		for pb.Next() {
			_, tracked, err := connections.Track(parent, users, user, conn)
			if err != nil {
				b.Error(err)
				return
			}
			tracked.Release()
		}
	})
}

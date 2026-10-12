package proxy

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// UserLookup returns the user an inbound currently accepts for an email, or
// nil. Validators that support RemoveUser implement it.
type UserLookup interface {
	GetByEmail(email string) *protocol.MemoryUser
}

// UserConnections lets an inbound close the live connections of a user it
// removes. Process tracks each connection it has authenticated for as long as
// it serves it; RemoveUser revokes the removed user after deleting it from the
// validator. Users are compared by pointer, so an inbound must store a fresh
// MemoryUser on every AddUser: a stale authentication of a removed user then
// never matches the user added again under the same email.
//
// The zero value is ready to use.
type UserConnections struct {
	mu    sync.Mutex
	users map[*protocol.MemoryUser]*TrackedConnection // first of a list
}

// TrackedConnection is one tracked connection. Its Process releases it on
// return.
type TrackedConnection struct {
	registry   *UserConnections
	user       *protocol.MemoryUser
	conn       io.Closer
	cancel     context.CancelFunc
	prev, next *TrackedConnection
	revoked    bool // guarded by registry.mu
}

// Track registers conn, which Process received and serves for user, until
// Release. It returns the context to serve it with: Revoke cancels it and then
// closes conn. Track fails when users no longer maps the user's email to user,
// that is, when the user was removed or replaced after it authenticated; the
// caller then drops the connection. A user without an email cannot be removed
// and is not tracked.
func (c *UserConnections) Track(ctx context.Context, users UserLookup, user *protocol.MemoryUser, conn io.Closer) (context.Context, *TrackedConnection, error) {
	if user == nil || user.Email == "" {
		return ctx, nil, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	tracked := &TrackedConnection{registry: c, user: user, conn: conn, cancel: cancel}

	c.mu.Lock()
	// RemoveUser deletes the user from users before it calls Revoke, which
	// takes this lock: either Revoke finds this connection, or this check
	// fails.
	if users.GetByEmail(user.Email) != user {
		c.mu.Unlock()
		cancel()
		return nil, nil, errors.New("user ", user.Email, " was removed")
	}
	if c.users == nil {
		c.users = make(map[*protocol.MemoryUser]*TrackedConnection)
	}
	if first := c.users[user]; first != nil {
		tracked.next = first
		first.prev = tracked
	}
	c.users[user] = tracked
	c.mu.Unlock()
	return ctx, tracked, nil
}

// Release ends tracking and cancels the connection's context. It is a no-op
// on nil, so Process can defer it for an untracked user.
func (t *TrackedConnection) Release() {
	if t == nil {
		return
	}
	c := t.registry
	c.mu.Lock()
	if !t.revoked {
		t.unlink()
	}
	c.mu.Unlock()
	t.cancel()
}

func (t *TrackedConnection) unlink() {
	c := t.registry
	if t.prev != nil {
		t.prev.next = t.next
	} else if t.next != nil {
		c.users[t.user] = t.next
	} else {
		delete(c.users, t.user)
	}
	if t.next != nil {
		t.next.prev = t.prev
	}
	t.prev, t.next = nil, nil
}

// Revoke cancels and closes every tracked connection of user. It does not
// wait for the closes: each runs in its own goroutine, so a connection whose
// Close blocks holds up neither the caller nor the other connections.
func (c *UserConnections) Revoke(user *protocol.MemoryUser) {
	c.mu.Lock()
	var revoked []*TrackedConnection
	for t := c.users[user]; t != nil; t = t.next {
		t.revoked = true
		revoked = append(revoked, t)
	}
	delete(c.users, user)
	c.mu.Unlock()

	// Cancel all first: canceling ends the work each Process waits on, and
	// closing the connection ends the reads and writes no context reaches.
	for _, t := range revoked {
		t.cancel()
	}
	for _, t := range revoked {
		go closeRevokedConnection(t.user.Email, t.conn)
	}
}

func closeRevokedConnection(email string, conn io.Closer) {
	if err := conn.Close(); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to close a connection of removed user ", email)
	}
}

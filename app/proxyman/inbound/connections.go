package inbound

import (
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// liveConnections are the connections a worker is serving, so that closing
// the worker ends them; otherwise removing an inbound or closing the instance
// left each one running until its Process returned. The zero value is ready
// to use.
type liveConnections struct {
	mu     sync.Mutex
	closed bool
	conns  map[*liveConnection]struct{}
}

type liveConnection struct {
	conn   io.Closer
	cancel context.CancelFunc
}

// add tracks conn, served under the context cancel ends, until remove. It
// returns nil once the worker has closed; the caller then drops conn.
func (s *liveConnections) add(conn io.Closer, cancel context.CancelFunc) *liveConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.conns == nil {
		s.conns = make(map[*liveConnection]struct{})
	}
	live := &liveConnection{conn: conn, cancel: cancel}
	s.conns[live] = struct{}{}
	return live
}

func (s *liveConnections) remove(live *liveConnection) {
	s.mu.Lock()
	delete(s.conns, live)
	s.mu.Unlock()
}

// closeAll stops admitting connections, cancels the context of every live
// one and closes it. Canceling ends what Process waits on; closing ends the
// reads and writes no context reaches. Each close runs in its own goroutine
// and nothing waits for it: a transport's Close can block, and the inbound
// manager holds its lock while it closes a handler.
func (s *liveConnections) closeAll() {
	s.mu.Lock()
	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	for live := range conns {
		live.cancel()
	}
	for live := range conns {
		go closeLiveConnection(live.conn)
	}
}

func closeLiveConnection(conn io.Closer) {
	// The worker closes the connection too once Process returns; whichever
	// Close comes second finds it closed.
	if err := conn.Close(); err != nil && !stderrors.Is(err, stdnet.ErrClosed) {
		errors.LogInfoInner(context.Background(), err, "failed to close a connection of a closed inbound")
	}
}

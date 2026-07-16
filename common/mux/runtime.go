package mux

import (
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
)

type runtimeWorker interface {
	Close() error
	WaitClosed() <-chan struct{}
}

type runtimeTicker interface {
	C() <-chan time.Time
	Stop()
}

type runtimeClock interface {
	Now() time.Time
	NewTicker(time.Duration) runtimeTicker
}

type realRuntimeClock struct{}

func (realRuntimeClock) Now() time.Time { return time.Now() }
func (realRuntimeClock) NewTicker(interval time.Duration) runtimeTicker {
	return realRuntimeTicker{Ticker: time.NewTicker(interval)}
}

type realRuntimeTicker struct{ *time.Ticker }

func (t realRuntimeTicker) C() <-chan time.Time { return t.Ticker.C }

// Runtime owns all long-lived state associated with one Mux owner.
type Runtime struct {
	mu        sync.Mutex
	workers   map[runtimeWorker]struct{}
	closing   bool
	closeOnce sync.Once
	closeErr  error
	xudpMu    sync.Mutex
	xudp      map[xudpKey]*XUDP
	xudpNonce uint64
	stop      chan struct{}
	stopped   chan struct{}
	clock     runtimeClock
}

func NewRuntime() *Runtime {
	return newRuntimeWithClock(realRuntimeClock{})
}

func newRuntimeWithClock(clock runtimeClock) *Runtime {
	runtime := &Runtime{
		workers: make(map[runtimeWorker]struct{}),
		xudp:    make(map[xudpKey]*XUDP),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
		clock:   clock,
	}
	go runtime.runExpiryScheduler()
	return runtime
}

func (r *Runtime) registerWorker(worker runtimeWorker) bool {
	if worker == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return false
	}
	r.workers[worker] = struct{}{}
	return true
}

func (r *Runtime) unregisterWorker(worker runtimeWorker) {
	r.mu.Lock()
	delete(r.workers, worker)
	r.mu.Unlock()
}

func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		workers := make([]runtimeWorker, 0, len(r.workers))
		for worker := range r.workers {
			workers = append(workers, worker)
		}
		r.mu.Unlock()

		for _, worker := range workers {
			if err := worker.Close(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
		}

		// Interrupt backend I/O before waiting for workers. A worker may be
		// blocked enqueueing XUDP data into a full backend pipe; interrupting
		// the flow is what makes that shutdown wait bounded.
		r.xudpMu.Lock()
		initialFlows := make([]*XUDP, 0, len(r.xudp))
		for _, flow := range r.xudp {
			initialFlows = append(initialFlows, flow)
		}
		r.xudpMu.Unlock()
		for _, flow := range initialFlows {
			flow.Interrupt()
		}
		for _, worker := range workers {
			<-worker.WaitClosed()
		}

		r.xudpMu.Lock()
		flows := make([]*XUDP, 0, len(r.xudp))
		for _, flow := range r.xudp {
			flows = append(flows, flow)
		}
		r.xudp = make(map[xudpKey]*XUDP)
		r.xudpMu.Unlock()
		for _, flow := range flows {
			flow.Interrupt()
		}
		for _, flow := range flows {
			flow.waitPumps()
		}
		close(r.stop)
		<-r.stopped
	})
	return r.closeErr
}

func (r *Runtime) runExpiryScheduler() {
	ticker := r.clock.NewTicker(time.Minute)
	defer ticker.Stop()
	defer close(r.stopped)
	for {
		select {
		case now := <-ticker.C():
			r.expireXUDPFlows(now)
		case <-r.stop:
			return
		}
	}
}

func (r *Runtime) expireXUDPFlows(now time.Time) {
	r.xudpMu.Lock()
	var expired []*XUDP
	for key, flow := range r.xudp {
		if flow.Status == Expiring && now.After(flow.Expire) {
			delete(r.xudp, key)
			expired = append(expired, flow)
		}
	}
	r.xudpMu.Unlock()
	for _, flow := range expired {
		flow.Interrupt()
		flow.waitPumps()
	}
}

func (r *Runtime) detachXUDPSession(session *Session) {
	if session == nil || session.XUDP == nil {
		return
	}
	r.xudpMu.Lock()
	flow := session.XUDP
	if flow.Attachment == session && flow.Generation == session.xudpGeneration {
		flow.Attachment = nil
		flow.Expire = r.clock.Now().Add(time.Minute)
		flow.Status = Expiring
	}
	r.xudpMu.Unlock()
}

func (r *Runtime) xudpKey(scope session.PresenceScope, mode session.PresenceMode, globalID [8]byte) xudpKey {
	key := xudpKey{GlobalID: globalID}
	if mode != session.PresenceModeStructural {
		return key
	}
	key.Principal = scope.Subject.PrincipalKey
	if !scope.Subject.Reusable && key.Principal == ([32]byte{}) {
		r.xudpMu.Lock()
		r.xudpNonce++
		key.Nonce = r.xudpNonce
		r.xudpMu.Unlock()
	}
	return key
}

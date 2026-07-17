package signal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.Mutex
	updated   chan struct{}
	checkTask *time.Timer
	timeout   time.Duration
	onTimeout func()
	consumed  atomic.Bool
	once      sync.Once
}

func (t *ActivityTimer) Update() {
	select {
	case t.updated <- struct{}{}:
	default:
	}
}

func (t *ActivityTimer) check() {
	t.mu.Lock()
	if t.consumed.Load() {
		t.mu.Unlock()
		return
	}
	select {
	case <-t.updated:
		t.checkTask.Reset(t.timeout)
		t.mu.Unlock()
	default:
		t.mu.Unlock()
		t.finish()
	}
}

func (t *ActivityTimer) finish() {
	t.once.Do(func() {
		t.consumed.Store(true)
		t.mu.Lock()
		if t.checkTask != nil {
			t.checkTask.Stop()
			t.checkTask = nil
		}
		t.mu.Unlock()
		t.onTimeout()
	})
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if t.consumed.Load() {
		return
	}
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	// double check, just in case
	if t.consumed.Load() {
		return
	}
	t.timeout = timeout
	select {
	case <-t.updated:
	default:
	}
	if t.checkTask == nil {
		t.checkTask = time.AfterFunc(timeout, t.check)
	} else {
		t.checkTask.Stop()
		t.checkTask.Reset(timeout)
	}
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	timer := &ActivityTimer{
		updated:   make(chan struct{}, 1),
		onTimeout: cancel,
	}
	timer.SetTimeout(timeout)
	return timer
}

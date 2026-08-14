package task

import (
	"sync"
	"time"
)

// Periodic is a task that runs periodically.
type Periodic struct {
	// Interval of the task being run
	Interval time.Duration
	// Execute is the task function
	Execute func() error

	access       sync.Mutex
	stateChanged *sync.Cond
	timer        *time.Timer
	running      bool
	closing      bool
	callbacks    int
}

func (t *Periodic) initStateChangedLocked() {
	if t.stateChanged == nil {
		t.stateChanged = sync.NewCond(&t.access)
	}
}

func (t *Periodic) checkedExecute() error {
	t.access.Lock()
	t.initStateChangedLocked()
	if !t.running || t.closing {
		t.access.Unlock()
		return nil
	}
	t.callbacks++
	t.access.Unlock()

	err := t.Execute()

	t.access.Lock()
	t.callbacks--
	t.stateChanged.Broadcast()
	if err != nil {
		t.running = false
		t.access.Unlock()
		return err
	}
	if t.running && !t.closing {
		t.timer = time.AfterFunc(t.Interval, func() {
			_ = t.checkedExecute()
		})
	}
	t.access.Unlock()
	return nil
}

// Start implements common.Runnable.
func (t *Periodic) Start() error {
	t.access.Lock()
	t.initStateChangedLocked()
	for t.closing {
		t.stateChanged.Wait()
	}
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.access.Unlock()

	return t.checkedExecute()
}

// Close implements common.Closable.
func (t *Periodic) Close() error {
	t.access.Lock()
	t.initStateChangedLocked()
	if t.closing {
		for t.closing {
			t.stateChanged.Wait()
		}
		t.access.Unlock()
		return nil
	}
	t.closing = true
	t.running = false
	t.stateChanged.Broadcast()
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	for t.callbacks != 0 {
		t.stateChanged.Wait()
	}
	t.closing = false
	t.stateChanged.Broadcast()
	t.access.Unlock()
	return nil
}

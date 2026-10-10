package outbound

import (
	"io"
	"sync"
	"time"
)

// connOwner owns the connections a test server accepts. Closing a listener
// leaves accepted connections open, so close closes each one, and any that is
// accepted afterwards, and waits for their readers.
type connOwner struct {
	mu      sync.Mutex
	conns   []io.Closer
	stopped bool
	readers sync.WaitGroup
}

// own takes conn together with one reader of it, which calls done when it
// ends. Once the owner has closed, own closes conn instead and returns false.
func (o *connOwner) own(conn io.Closer) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopped {
		_ = conn.Close()
		return false
	}
	o.conns = append(o.conns, conn)
	o.readers.Add(1)
	return true
}

func (o *connOwner) done() {
	o.readers.Done()
}

// close closes every owned connection and waits up to 5 s for their readers;
// it reports whether they ended. It may run more than once.
func (o *connOwner) close() bool {
	o.mu.Lock()
	o.stopped = true
	conns := o.conns
	o.conns = nil
	o.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	ended := make(chan struct{})
	go func() {
		o.readers.Wait()
		close(ended)
	}()
	select {
	case <-ended:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

package hysteria

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestUDPSessionManagerDoesNotBlockNewSessions(t *testing.T) {
	started := make(chan uint32, 2)
	release := make(chan struct{})
	finished := make(chan struct{}, 2)
	manager := &udpSessionManager{
		addConn: func(conn stat.Connection) {
			started <- conn.(*InterConn).id
			<-release
			finished <- struct{}{}
		},
	}

	dispatched := make(chan struct{})
	go func() {
		manager.dispatchConnection(&InterConn{id: 1})
		manager.dispatchConnection(&InterConn{id: 2})
		close(dispatched)
	}()

	seen := make(map[uint32]bool, 2)
	for len(seen) < 2 {
		select {
		case id := <-started:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatalf("new UDP session blocked behind active session; started IDs: %v", seen)
		}
	}
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		t.Fatal("UDP session dispatch remained blocked")
	}

	close(release)
	for range 2 {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("UDP session handler did not finish")
		}
	}
}

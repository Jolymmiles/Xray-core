package xdns

import "testing"

func testClientID(i int) ClientID {
	return ClientIDFromRaw([8]byte{0, 0, 0, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// Per-client send queues are created from client-chosen IDs before any
// authentication, so the table must stay bounded while known clients keep
// their queues. From TaiLerV's sync/upstream-2026-10-02 branch.
func TestSendManagerBoundsClientQueues(t *testing.T) {
	m := NewSendManager()
	defer m.Close()

	for i := range sendClientCount {
		if _, _, ok := m.Pop(testClientID(i)); !ok {
			t.Fatalf("client %d refused below the limit", i)
		}
	}
	if _, _, ok := m.Pop(testClientID(sendClientCount)); ok {
		t.Fatal("a client beyond the limit got a queue")
	}
	m.Push(testClientID(sendClientCount+1), []byte("over limit"))
	m.mu.Lock()
	tracked := len(m.m)
	m.mu.Unlock()
	if tracked != sendClientCount {
		t.Fatalf("tracked clients = %d, want %d", tracked, sendClientCount)
	}

	known := testClientID(7)
	m.Push(known, []byte("data"))
	ch, _, ok := m.Pop(known)
	if !ok {
		t.Fatal("a known client lost its queue at the limit")
	}
	if got := <-ch; string(got) != "data" {
		t.Fatalf("queued %q, want data", got)
	}
}

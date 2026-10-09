package xdns

import (
	"bytes"
	stdnet "net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// testClientID returns a distinct client ID for each i.
func testClientID(i int) ClientID {
	return ClientIDFromRaw([8]byte{0, 0, 0, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// isTracked reports whether m holds queues for clientID.
func isTracked(m *SendManager, clientID ClientID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[clientID] != nil
}

// trackedClients returns how many clients m holds queues for.
func trackedClients(m *SendManager) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// Per-client send queues are created from client-chosen IDs before any
// authentication, so the table must stay bounded. From TaiLerV's
// sync/upstream-2026-10-02 branch. A full table must still admit new
// clients: refusing them let a flood of polls lock every new client out, so
// the least recently used client gives up its queue instead.
func TestSendManagerEvictsLeastRecentlyUsedClientAtLimit(t *testing.T) {
	m := NewSendManager()
	defer m.Close()

	for i := range sendClientCount {
		if _, _, ok := m.Pop(testClientID(i)); !ok {
			t.Fatalf("client %d refused below the limit", i)
		}
	}
	// Client 0 polls again, which leaves client 1 the least recently used.
	m.Pop(testClientID(0))

	if _, _, ok := m.Pop(testClientID(sendClientCount)); !ok {
		t.Fatal("a new client was refused at the limit")
	}
	m.Push(testClientID(sendClientCount+1), []byte("new"))
	if got := trackedClients(m); got != sendClientCount {
		t.Fatalf("tracked clients = %d, want %d", got, sendClientCount)
	}
	for _, evicted := range []int{1, 2} {
		if isTracked(m, testClientID(evicted)) {
			t.Fatalf("least recently used client %d kept its queue", evicted)
		}
	}
	if !isTracked(m, testClientID(0)) {
		t.Fatal("a recently used client lost its queue")
	}

	m.Push(testClientID(7), []byte("data"))
	for _, queued := range []struct {
		id   ClientID
		want string
	}{
		{testClientID(sendClientCount + 1), "new"},
		{testClientID(7), "data"},
	} {
		ch, _, ok := m.Pop(queued.id)
		if !ok {
			t.Fatalf("client %x lost its queue at the limit", queued.id)
		}
		select {
		case got := <-ch:
			if string(got) != queued.want {
				t.Fatalf("client %x got %q, want %q", queued.id, got, queued.want)
			}
		default:
			t.Fatalf("client %x has no queued data, want %q", queued.id, queued.want)
		}
	}
}

// pollQuery packs the empty poll a client sends when it has no data.
func pollQuery(t *testing.T, domain *Domain, clientID ClientID, id uint16) []byte {
	t.Helper()
	var data [17]byte
	copy(data[:], clientID[:])
	data[0] |= TypeMap[TypeTXT]
	data[8] = 8
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: domain.Encode(data[:]), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// floodPolls sends one poll for each of count fresh client IDs and waits for
// every reply, keeping at most window queries in flight.
func floodPolls(t *testing.T, server stdnet.Addr, domain *Domain, count int) {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	replies := make(chan struct{}, count)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
			replies <- struct{}{}
		}
	}()
	awaitReply := func(sent int) {
		select {
		case <-replies:
		case <-time.After(5 * time.Second):
			t.Fatalf("no reply after %d polls", sent)
		}
	}
	const window = 64
	for i := range count {
		if i >= window {
			awaitReply(i)
		}
		if _, err := conn.WriteTo(pollQuery(t, domain, testClientID(i), uint16(i)), server); err != nil {
			t.Fatal(err)
		}
	}
	for range min(count, window) {
		awaitReply(count)
	}
}

// Polls from unauthenticated senders fill the send table. A client that
// arrives while it is full must still get the data the upper layer sends it.
func TestServerAdmitsNewClientDuringPollFlood(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewServer(testServerConfig(), raw)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	server := conn.(*xdnsServer)
	domain := server.domains[0]

	floodPolls(t, raw.LocalAddr(), domain, sendClientCount+64)
	if got := trackedClients(server.sendManager); got != sendClientCount {
		t.Fatalf("tracked clients after the flood = %d, want %d", got, sendClientCount)
	}

	newcomer := ClientIDFromRaw([8]byte{0x0C, 0xAA, 0, 0, 0, 0, 0, 1})
	payload := []byte("downstream-hello")
	if _, err := server.WriteTo(payload, newcomer.Addr()); err != nil {
		t.Fatal(err)
	}
	var query dnsmessage.Message
	if err := query.Unpack(pollQuery(t, domain, newcomer, 0x7777)); err != nil {
		t.Fatal(err)
	}
	reply, err := exchange(t, raw.LocalAddr(), query)
	if err != nil {
		t.Fatalf("the new client's poll got no reply: %v", err)
	}
	decoded := make([]byte, 4096)
	n := NewResp(reply, domain, 0).Decode(decoded)
	if n < 2 || !bytes.Equal(decoded[2:n], payload) {
		t.Fatalf("the new client received %q, want its packet %q", decoded[:n], payload)
	}
}

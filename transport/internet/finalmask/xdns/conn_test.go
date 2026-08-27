package xdns

import (
	go_errors "errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeUDP is an in-memory net.PacketConn stand-in for the UDP socket below
// xdns. Reads block until Close so the internal lifecycle loops see realistic
// socket semantics.
type fakeUDP struct {
	closeCh chan struct{}
	once    sync.Once

	mu      sync.Mutex
	written [][]byte
	addrs   []net.Addr
}

func newFakeUDP() *fakeUDP { return &fakeUDP{closeCh: make(chan struct{})} }

func (f *fakeUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	<-f.closeCh
	return 0, nil, net.ErrClosed
}

func (f *fakeUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	buf := make([]byte, len(p))
	copy(buf, p)
	f.written = append(f.written, buf)
	f.addrs = append(f.addrs, addr)
	return len(p), nil
}

func (f *fakeUDP) Close() error {
	f.once.Do(func() { close(f.closeCh) })
	return nil
}

func (f *fakeUDP) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakeUDP) SetDeadline(time.Time) error      { return nil }
func (f *fakeUDP) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeUDP) SetWriteDeadline(time.Time) error { return nil }

var testDomain = func() Name {
	name, err := NewName([][]byte{[]byte("t"), []byte("example")})
	if err != nil {
		panic(err)
	}
	return name
}()

// newTestServer wires a ConnServer to a fake socket with tightened timing
// knobs so lifecycle tests stay fast and deterministic. It returns the
// connection plus a cleanup func that must be deferred.
func newTestServer(t *testing.T, maxQ int) (*xdnsConnServer, *fakeUDP, func()) {
	t.Helper()

	savedMax := maxQueues
	savedIdle := idleTimeout
	savedDelay := maxResponseDelay
	maxQueues = maxQ
	idleTimeout = time.Second
	maxResponseDelay = 5 * time.Millisecond

	conn := &xdnsConnServer{
		PacketConn:    newFakeUDP(),
		domains:       []domainSpec{{name: testDomain}},
		ch:            make(chan *record, 500),
		readQueue:     make(chan *packet, 512),
		writeQueueMap: make(map[string]*queue),
	}

	cleanDone := make(chan struct{})
	go func() {
		conn.clean()
		close(cleanDone)
	}()
	go conn.recvLoop()
	go conn.sendLoop()

	cleanup := func() {
		_ = conn.Close()
		<-cleanDone
		maxQueues = savedMax
		idleTimeout = savedIdle
		maxResponseDelay = savedDelay
	}
	return conn, conn.PacketConn.(*fakeUDP), cleanup
}

// noErrorResponse fakes the response shell sendLoop groups answers into.
func noErrorResponse(id uint16) *Message {
	return &Message{
		ID:       id,
		Flags:    0x8000,
		Question: []Question{{Name: testDomain, Type: RRTypeTXT, Class: ClassIN}},
	}
}

// clientAddr maps a small counter onto the synthetic fd00::/8 space the
// server derives from decoded clientIDs.
func clientAddr(n int) net.Addr {
	var id [8]byte
	id[0] = byte(n)
	id[1] = byte(n >> 8)
	return clientIDToAddr(id)
}

func newTestClient(t *testing.T) net.PacketConn {
	t.Helper()

	c := &Config{
		Resolvers: []string{"t.example+udp://127.0.0.1:53", "a.example+udp://127.0.0.2:53"},
	}
	conn, err := NewConnClient(c, newFakeUDP())
	if err != nil {
		t.Fatalf("NewConnClient: %v", err)
	}
	return conn
}

// TestXdnsConcurrentLifecycleStress hammers WriteTo/ReadFrom/Close from many
// goroutines so the race detector polices every shared-field access between
// sendLoop, recvLoop and packet users.
func TestXdnsConcurrentLifecycleStress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T) net.PacketConn
	}{
		{"client", newTestClient},
		{"server", func(t *testing.T) net.PacketConn {
			c, _, cleanup := newTestServer(t, 32)
			t.Cleanup(cleanup)
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := tc.build(t)

			const workers = 4
			var wg sync.WaitGroup
			stop := make(chan struct{})
			// Close from a timer: blocked readers only drain once the
			// lifecycle loops tear their queues down.
			time.AfterFunc(400*time.Millisecond, func() { _ = conn.Close() })
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					buf := make([]byte, 64)
					i := 0
					for {
						select {
						case <-stop:
							return
						default:
						}
						addr := clientAddr(w*1000 + i)
						if i%2 == 0 {
							if _, err := conn.WriteTo(buf[:30], addr); err != nil {
								return
							}
						} else {
							if _, _, err := conn.ReadFrom(buf); err != nil {
								return
							}
						}
						i++
					}
				}(w)
			}

			time.Sleep(700 * time.Millisecond)
			close(stop)
			wg.Wait()
			// Double close must stay safe; wrappers own their socket.
			_ = conn.Close()
		})
	}
}

func TestServerWriteQueueMapBounded(t *testing.T) {
	conn, _, cleanup := newTestServer(t, 16)
	defer cleanup()

	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	mapLen := func() int {
		conn.mutex.Lock()
		defer conn.mutex.Unlock()
		return len(conn.writeQueueMap)
	}

	for i := 0; i < 128; i++ {
		select {
		case conn.ch <- &record{Resp: noErrorResponse(uint16(i)), Addr: local, ClientAddr: clientAddr(i)}:
		case <-time.After(2 * time.Second):
			t.Fatalf("stuck feeding record %d", i)
		}
		if got := mapLen(); got > maxQueues {
			cleanup()
			t.Fatalf("writeQueueMap grew to %d, cap %d", got, maxQueues)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for mapLen() < maxQueues && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := mapLen(); got > maxQueues {
		t.Fatalf("map size %d exceeds cap %d", got, maxQueues)
	}
	if mapLen() != maxQueues {
		t.Fatalf("precondition failed: table has %d entries, want %d", mapLen(), maxQueues)
	}

	n, err := conn.WriteTo([]byte("x"), clientAddr(100000))
	if n != 0 || !go_errors.Is(err, errQueueLimitReached) {
		t.Fatalf("over-cap WriteTo returned (%d, %v), want (0, errQueueLimitReached)", n, err)
	}
}

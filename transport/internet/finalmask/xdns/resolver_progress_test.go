package xdns

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type resolverObserver struct {
	*fakeUDP
	writes chan string
}

func (c *resolverObserver) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes <- addr.String()
	return len(p), nil
}

func TestClientSkipsBusyResolvers(t *testing.T) {
	for _, resolverCount := range []int{2, 3} {
		t.Run(strconv.Itoa(resolverCount), func(t *testing.T) {
			conn := newTestClientDirect(4)
			socket := &resolverObserver{fakeUDP: newFakeUDP(), writes: make(chan string, 4)}
			conn.PacketConn = socket
			for i := 1; i < resolverCount; i++ {
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(i+1)), Port: 53}
				conn.resolverAddrs = append(conn.resolverAddrs, addr)
				conn.resolverTypes = append(conn.resolverTypes, RRTypeTXT)
				conn.domains = append(conn.domains, testDomain)
				conn.resolverSend[addr.String()] = new(atomic.Uint32)
			}
			conn.resolverSend[conn.resolverAddrs[1].String()].Store(1)
			conn.writeQueue <- &packet{p: []byte("first")}
			conn.writeQueue <- &packet{p: []byte("second")}
			done := make(chan struct{})
			go func() { defer close(done); conn.sendLoop() }()
			t.Cleanup(func() {
				_ = conn.Close()
				// Unblock the broken selector too, so a failed assertion cannot leak it.
				for _, count := range conn.resolverSend {
					count.Store(0)
				}
				close(conn.writeQueue)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("send loop did not stop")
				}
			})
			for i := 0; i < 2; i++ {
				select {
				case addr := <-socket.writes:
					want := conn.resolverAddrs[0].String()
					if i == 1 && resolverCount == 3 {
						want = conn.resolverAddrs[2].String()
					}
					if addr != want {
						t.Fatalf("write %d resolver = %s, want %s", i, addr, want)
					}
				case <-time.After(time.Second):
					t.Fatalf("write %d stalled behind a busy resolver", i)
				}
			}
		})
	}
}

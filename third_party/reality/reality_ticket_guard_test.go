package reality

import (
	"container/list"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTicketHelloGuardRejectsConcurrentDuplicates(t *testing.T) {
	cache := &ticketHelloCache{size: 4, entries: make(map[[32]byte]*list.Element)}
	now := time.Now()
	hello := []byte("authenticated hello")
	key := sha256.Sum256(hello)
	hs := &serverHandshakeStateTLS13{
		c:           &Conn{},
		clientHello: &clientHelloMsg{original: append(hello, 0, 4, 1, 1, 1, 2), pskBinders: [][]byte{{1}, {2}}},
	}
	if !cache.acceptClientHello(hs, now, true) || len(cache.entries) != 0 {
		t.Fatal("browser-off connection entered the replay cache")
	}
	hs.c.realityTickets = true
	if !cache.acceptClientHello(hs, now, false) || len(cache.entries) != 0 {
		t.Fatal("an unvalidated binder reserved an authenticated ClientHello")
	}
	var accepted atomic.Int32
	var calls sync.WaitGroup
	for range 32 {
		calls.Go(func() {
			if cache.acceptClientHello(hs, now, true) {
				accepted.Add(1)
			}
		})
	}
	calls.Wait()
	if count := accepted.Load(); count != 1 {
		t.Fatalf("accepted %d copies of one authenticated ClientHello, want 1", count)
	}
	if cache.acceptClientHello(hs, now, false) {
		t.Fatal("a known ClientHello was admitted after its ticket became unrecognizable")
	}
	hs.clientHello.pskBinders[1] = []byte{3}
	hs.clientHello.original[len(hs.clientHello.original)-1] = 3
	if cache.acceptClientHello(hs, now, true) {
		t.Fatal("changing an unselected binder bypassed the replay guard")
	}
	hs.clientHello.original[0] = 'A'
	if !cache.acceptClientHello(hs, now, true) {
		t.Fatal("a distinct ClientHello was refused")
	}
	if expiry := cache.entries[key].Value.(seenTicketHello).expires; !expiry.Equal(now.Add(maxSessionTicketLifetime + time.Minute)) {
		t.Fatalf("cache expiry %v does not cover the longest ticket acceptance window", expiry)
	}
}

func TestTicketHelloCacheKeepsBoundAndExpires(t *testing.T) {
	cache := &ticketHelloCache{size: 2, entries: make(map[[32]byte]*list.Element)}
	now := time.Now()
	a, b, c := [32]byte{1}, [32]byte{2}, [32]byte{3}
	expires := now.Add(time.Minute)
	if !cache.accept(a, now, expires, true) || !cache.accept(b, now, expires, true) {
		t.Fatal("a new key was refused")
	}
	if cache.accept(a, now, expires, true) || !cache.accept(c, now, expires, true) {
		t.Fatal("a duplicate was admitted or a new key was refused")
	}
	if cache.entries[a] != nil || len(cache.entries) != 2 || cache.order.Len() != 2 {
		t.Fatal("cache did not evict the oldest key")
	}
	if !cache.accept(b, expires, expires.Add(time.Minute), true) || cache.order.Len() != 2 {
		t.Fatal("an expired entry was not replaced")
	}
}

func TestClassifyEmptyBinderRefusal(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		err   error
		after time.Duration
		kind  refusalKind
		delay time.Duration
	}{
		{"early EOF", io.EOF, time.Millisecond, finRefusal, time.Millisecond},
		{"delayed EOF", io.EOF, 3 * time.Second, finRefusal, 3 * time.Second},
		{"early timeout", os.ErrDeadlineExceeded, time.Second, noRefusal, 0},
		{"silent", os.ErrDeadlineExceeded, badBinderWait, silentRefusal, badBinderWait},
		{"other read error", net.ErrClosed, time.Millisecond, noRefusal, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &probeCaptureConn{readErr: tc.err, readEnd: now.Add(tc.after)}
			reply := classifyBinderRefusal(capture, now)
			if reply.kind != tc.kind || reply.delay != tc.delay || len(reply.alerts) != 0 {
				t.Fatalf("got %+v, want kind %v after %v", reply, tc.kind, tc.delay)
			}
		})
	}
}

func TestBinderSilenceNeedsTwoMeasurements(t *testing.T) {
	for _, second := range []refusalKind{silentRefusal, resetRefusal} {
		count := 0
		reply := confirmBinderRefusal(func() binderRefusal {
			count++
			if count == 1 {
				return binderRefusal{kind: silentRefusal, delay: badBinderWait}
			}
			return binderRefusal{kind: second}
		})
		want := noRefusal
		if second == silentRefusal {
			want = silentRefusal
		}
		if count != 2 || reply.kind != want {
			t.Fatalf("second measurement %v: got %v after %d probes", second, reply.kind, count)
		}
	}
}

type refusalTestConn struct{ CloseWriteConn }

func (c refusalTestConn) NetConn() net.Conn { return c.CloseWriteConn }

func TestRefusalCloseOnTCP(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind refusalKind
	}{
		{"FIN", finRefusal},
		{"RST", resetRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			tcp, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			wrapped := refusalTestConn{tcp}
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			const delay = 30 * time.Millisecond
			start := time.Now()
			done := make(chan struct{})
			go func() {
				defer close(done)
				closeAfterRefusal(wrapped, wrapped, &TicketShape{badBinderClose: tc.kind, BadBinderDelay: delay})
			}()
			if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var buf [1]byte
			n, err := client.Read(buf[:])
			if n != 0 || (tc.kind == finRefusal && !errors.Is(err, io.EOF)) ||
				(tc.kind == resetRefusal && !connectionWasReset(err)) {
				t.Fatalf("peer read = %d, %v, want %s without data", n, err, tc.name)
			}
			if elapsed := time.Since(start); elapsed < delay {
				t.Fatalf("peer saw %s after %v, want at least %v", tc.name, elapsed, delay)
			}
			var capture probeCaptureConn
			capture.readErr, capture.readEnd = err, time.Now()
			if reply := classifyBinderRefusal(&capture, capture.readEnd); reply.kind != tc.kind {
				t.Fatalf("peer error %v mapped to kind %v, want %v", err, reply.kind, tc.kind)
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not close the connection")
			}
		})
	}
}

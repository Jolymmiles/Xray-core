package splithttp

// A governed client in front of a governed server. Both governors are real
// flowConns, driven frame by frame in memory; the local Go client and the
// local HTTP/2 server are scripted. No sleeps, no timers.

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// chain is cg (client-side governor) -> wire -> h.c (server-side governor).
type chain struct {
	t     *testing.T
	cconn *scriptConn
	cg    *flowConn
	h     *flowHarness
}

func newChain(t *testing.T, sendWindow int64) *chain {
	t.Helper()
	cc := &scriptConn{}
	ch := &chain{t: t, cconn: cc, cg: newFlowClientConn(cc), h: newFlowHarnessNoPreface(t)}
	ch.h.c.sendWindow = sendWindow
	t.Cleanup(func() { ch.cg.Close(); ch.h.c.Close() })
	return ch
}

// newFlowHarnessNoPreface is newFlowHarness without feeding the preface: the
// preface arrives through the client governor.
func newFlowHarnessNoPreface(t *testing.T) *flowHarness {
	sc := &scriptConn{}
	return &flowHarness{t: t, conn: sc, c: newFlowConn(sc, flowDefault, flowDefault)}
}

// fromLocalClient sends b from the local client stack through both governors
// and returns what the local server stack reads.
func (ch *chain) fromLocalClient(b []byte) []byte {
	ch.t.Helper()
	if _, err := ch.cg.Write(b); err != nil {
		ch.t.Fatalf("client governor write: %v", err)
	}
	return ch.h.fromClientRaw(ch.cconn.take())
}

func (ch *chain) clientFrames(f func(fr *http2.Framer)) []byte {
	return ch.fromLocalClient(frames(f))
}

// fromLocalServer sends frames from the local server stack through both
// governors and returns what the local client stack reads.
func (ch *chain) fromLocalServer(f func(fr *http2.Framer)) []byte {
	ch.t.Helper()
	wire, err := ch.h.fromServerRaw(frames(f))
	if err != nil {
		ch.t.Fatalf("server write: %v", err)
	}
	ch.cconn.feed(wire)
	var got []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := ch.cg.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				ch.t.Fatalf("client governor read: %v", err)
			}
			return got
		}
	}
}

// start: Go client preface, SETTINGS 4 MiB stream window, connection window
// raised to 1 GiB; server SETTINGS.
func (ch *chain) start() {
	ch.fromLocalClient([]byte(h2Preface))
	ch.h.track()
	ch.clientFrames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
		fr.WriteWindowUpdate(0, 1<<30-h2InitWindow)
	})
	ch.fromLocalServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	})
}

func (ch *chain) open(id uint32) {
	ch.clientFrames(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
	})
}

// sendAll has the local server send all the window it has on id.
func (ch *chain) sendAll(id uint32) int64 {
	w := ch.h.toServer.streams[id]
	if w <= 0 {
		return 0
	}
	ch.fromLocalServer(func(fr *http2.Framer) { writeDataSplit(fr, id, int(w)) })
	ch.h.toServer.streams[id] -= w
	return w
}

// TestFlowChainedStallAtSendWindow has a governed client in front of a
// governed server whose connection is at its send window. The client governor
// showed the server 65535 and counts on all of it. A server that showed its
// own stack less (flowShownLimited) kept the difference back at
// the limit, the client governor took it for window the sender had, and a
// slow reader whose client cap had shrunk to init then returned nothing: the
// download stopped for good, even once the limit was free. Nothing here sets
// a cap or a measured flag: the test only moves the reader's round-trip mark
// so that every credit closes a slow round.
func TestFlowChainedStallAtSendWindow(t *testing.T) {
	for _, limit := range []int64{0, flowServerSendWindow} {
		t.Run(fmt.Sprintf("send window %d", limit), func(t *testing.T) {
			ch := newChain(t, limit)
			ch.start()
			// A first download read as a Go client reads it: stream credit
			// in a small step, the tail returned through the connection.
			ch.open(1)
			ch.fromLocalServer(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
				writeDataSplit(fr, 1, 32768)
			})
			ch.clientFrames(func(fr *http2.Framer) {
				fr.WriteWindowUpdate(1, 32768)
				fr.WriteWindowUpdate(0, 32768)
			})
			ch.fromLocalServer(func(fr *http2.Framer) { fr.WriteData(1, true, make([]byte, 8192)) })
			ch.clientFrames(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 8192) })
			if !ch.h.c.incremental {
				t.Fatal("the server governor has not seen small stream credit")
			}
			// Downloads the server ends and the client has not read yet
			// fill the limit.
			unread, id := int64(0), uint32(3)
			for ; unread < 5<<20; id += 2 {
				ch.open(id)
				ch.fromLocalServer(func(fr *http2.Framer) {
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x88}, EndHeaders: true})
				})
				unread += ch.sendAll(id)
				ch.fromLocalServer(func(fr *http2.Framer) { fr.WriteData(id, true, nil) })
			}
			// A slow download: the reader takes 4 KiB per round trip.
			b := id
			ch.open(b)
			ch.fromLocalServer(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: b, BlockFragment: []byte{0x88}, EndHeaders: true})
			})
			buffered := int64(0)
			for round := 0; round < 400; round++ {
				buffered += ch.sendAll(b)
				if buffered < 4096 {
					break
				}
				ch.cg.mu.Lock()
				ch.cg.streams[b].down.mark = time.Now().Add(-2 * ch.cg.currentRTT())
				ch.cg.mu.Unlock()
				ch.clientFrames(func(fr *http2.Framer) {
					fr.WriteWindowUpdate(b, 4096)
					fr.WriteWindowUpdate(0, 4096)
				})
				buffered -= 4096
			}
			ch.cg.mu.Lock()
			cs := ch.cg.streams[b]
			cap, belief := cs.down.cap, int64(ch.cg.clientShown)+cs.downForwarded-cs.downSent
			ch.cg.mu.Unlock()
			t.Logf("client cap %d (init %d), client unread %d, client governor counts on %d more from the server, server stack window %d",
				cap, ch.cg.down.init, buffered, belief, ch.h.toServer.streams[b])
			// The client reads every ended download: the limit frees.
			for left := unread; left > 0; left -= min(left, 16<<10) {
				n := min(left, 16<<10)
				ch.clientFrames(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, uint32(n)) })
			}
			if w := ch.h.toServer.streams[b]; w <= 0 {
				t.Fatalf("stream %d: the server may send %d more and the client has %d bytes it cannot return: stopped for good",
					b, w, buffered)
			}
		})
	}
}

// TestFlowChainedClientNotHeldToSendWindow fixes what the send window does not
// do. Forty downloads open from a governed client, the server sends all it
// may and the client reads nothing. The client governor opens each stream
// with credit of its cap above what it showed, and the server governor hands
// all of that on: a client that shows no more than the protocol default is
// shown all of it, see shownDown. What such a client holds is up to its own
// governor, forty times its starting cap here, with the limit as without.
func TestFlowChainedClientNotHeldToSendWindow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sendWindow int64
		connCredit bool
	}{{"no send window", 0, false}, {"default send window", flowServerSendWindow, false}, {"default send window, connection credit seen", flowServerSendWindow, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ch := newChain(t, tc.sendWindow)
			ch.start()
			first := uint32(1)
			if tc.connCredit {
				// One small download read to the end, returned through
				// the connection in a small step: the connection count is on.
				ch.open(1)
				ch.fromLocalServer(func(fr *http2.Framer) {
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
					fr.WriteData(1, true, make([]byte, 8<<10))
				})
				ch.clientFrames(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, 8<<10) })
				if !ch.h.c.downConnSmall {
					t.Fatal("connection count not on")
				}
				first = 3
			}
			total := int64(0)
			for i := 0; i < 40; i++ {
				id := first + uint32(2*i)
				ch.open(id)
				ch.fromLocalServer(func(fr *http2.Framer) {
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x88}, EndHeaders: true})
				})
				total += ch.sendAll(id)
			}
			t.Logf("governed client, 40 unread downloads: client holds %d unread (limit %d); server governor counts %d", total, tc.sendWindow, ch.h.c.clientHolds())
			if total != 40*flowStartWindow {
				t.Fatalf("a governed client was sent %d on forty streams, want its own governor's %d each, %d", total, flowStartWindow, 40*flowStartWindow)
			}
		})
	}
}

// TestFlowSendWindowRaiseDropsUnread fixes a limit of the connection's count.
// Downloads the server has ended lie unread, and the client sends a
// connection WINDOW_UPDATE that takes its window above where it has been. A
// raise cannot be told from the return of what was read in such a credit, so
// it is taken for a raise and the unread data drops out of the count: the
// count errs towards sending. Xray and Mihomo clients raise their window
// once, at the start.
func TestFlowSendWindowRaiseDropsUnread(t *testing.T) {
	h := openStreams(t, flowServerSendWindow, 4<<20, 0)
	t.Cleanup(func() { h.c.Close() })
	goClientStart(t, h)
	sent := finishedRounds(h, 1)[0]
	if before := h.c.clientHolds(); before != sent {
		t.Fatalf("%d unread, counted %d", sent, before)
	}
	h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, uint32(sent+h2MinMaxFrameSize)) })
	if after := h.c.clientHolds(); after != 0 {
		t.Fatalf("after a raise past the high mark the count is %d, want 0", after)
	}
}

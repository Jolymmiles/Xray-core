package splithttp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// scriptConn stands in for the TLS connection under a server-side governor:
// Read serves the bytes the test queued as the client's and then reports a
// timeout, Write records what reaches the client, and Close is observable.
type scriptConn struct {
	net.Conn
	mu       sync.Mutex
	in       bytes.Buffer
	out      bytes.Buffer
	closed   bool
	failNext bool
}

func (c *scriptConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.in.Len() == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	return c.in.Read(b)
}

// Write accepts everything except, once failNext is set, a single write that
// lands only in part, the way a socket reports a short write.
func (c *scriptConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.failNext {
		c.failNext = false
		n := len(b) / 2
		c.out.Write(b[:n])
		return n, io.ErrShortWrite
	}
	return c.out.Write(b)
}

func (c *scriptConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *scriptConn) feed(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.in.Write(b)
}

func (c *scriptConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := append([]byte(nil), c.out.Bytes()...)
	c.out.Reset()
	return b
}

func (c *scriptConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// flowHarness drives a server-side governor through its real Read and Write
// paths: the client's frames go in through Read, the server's through Write.
type flowHarness struct {
	t       testing.TB
	conn    *scriptConn
	c       *flowConn
	readErr error

	// toServer and toClient, once track is called, follow the send windows
	// of the server and the client from the frames each one reads.
	toServer, toClient *sendView
}

func (h *flowHarness) track() {
	h.toServer, h.toClient = newSendView(), newSendView()
}

func newFlowHarness(t *testing.T) *flowHarness {
	t.Helper()
	sc := &scriptConn{}
	h := &flowHarness{t: t, conn: sc, c: newFlowConn(sc, flowDefault, flowDefault)}
	if got := h.fromClientRaw([]byte(h2Preface)); string(got) != h2Preface {
		t.Fatalf("preface reached the server as %q", got)
	}
	return h
}

func frames(f func(fr *http2.Framer)) []byte {
	var b bytes.Buffer
	fr := http2.NewFramer(&b, nil)
	fr.AllowIllegalWrites = true
	f(fr)
	return b.Bytes()
}

// fromClientRaw hands b to the governor as bytes the client sent and returns
// what the server's HTTP/2 stack reads. A read error other than the script
// running dry is kept in readErr.
func (h *flowHarness) fromClientRaw(b []byte) []byte {
	h.conn.feed(b)
	var got []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := h.c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) && h.readErr == nil {
				h.readErr = err
			}
			break
		}
	}
	h.sync()
	if h.toServer != nil {
		h.toServer.receive(h.t, got)
	}
	h.checkHolds()
	return got
}

// checkHolds compares the counters behind clientHolds, which are kept as the
// streams change, with a walk over the streams.
func (h *flowHarness) checkHolds() {
	h.t.Helper()
	c := h.c
	c.mu.Lock()
	defer c.mu.Unlock()
	var open, forwarded, returned int64
	for _, s := range c.streams {
		if !s.serverDone {
			open++
			forwarded += s.downForwarded
			returned += s.down.returned
		}
	}
	if open != c.downOpen || forwarded != c.downOpenForwarded || returned != c.downOpenReturned {
		h.t.Fatalf("unfinished streams: %d forwarded %d returned %d, the connection counts %d forwarded %d returned %d",
			open, forwarded, returned, c.downOpen, c.downOpenForwarded, c.downOpenReturned)
	}
}

func (h *flowHarness) fromClient(f func(fr *http2.Framer)) []byte {
	return h.fromClientRaw(frames(f))
}

// fromServerRaw writes b as the server's HTTP/2 stack would and returns what
// reaches the client, injected frames included.
func (h *flowHarness) fromServerRaw(b []byte) ([]byte, error) {
	_, err := h.c.Write(b)
	h.sync()
	got := h.conn.take()
	if h.toClient != nil {
		h.toClient.receive(h.t, got)
	}
	h.checkHolds()
	return got, err
}

func (h *flowHarness) fromServer(f func(fr *http2.Framer)) []byte {
	got, err := h.fromServerRaw(frames(f))
	if err != nil {
		h.t.Fatalf("server write: %v", err)
	}
	return got
}

// sync waits for a frame injection that is holding the write side.
func (h *flowHarness) sync() {
	h.c.wmu.Lock()
	//nolint:staticcheck // empty critical section: only waits for the holder
	h.c.wmu.Unlock()
}

// dueForPing lets the next frame boundary towards the client carry a PING.
// Adapted to bdbac60e: the governor now sends a PING with its first SETTINGS
// and keeps a single outstanding PING, so the earlier one is treated as timed
// out, which is what the governor itself does after flowPingTimeout.
func (h *flowHarness) dueForPing() {
	h.c.mu.Lock()
	h.c.lastPing = time.Time{}
	h.c.pingSentAt = time.Time{}
	h.c.mu.Unlock()
}

// openStream runs the usual start of a connection: the client announces
// clientWindow, the server announces 1 MiB, and the client opens stream 1.
// It returns what reached the server when the stream opened.
func (h *flowHarness) openStream(clientWindow uint32) []byte {
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: clientWindow})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(
			http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 20},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
		)
	})
	return h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
}

// sendView follows the send windows of one peer the way a stock HTTP/2 stack
// does: streams start at the initial window it was told, WINDOW_UPDATE adds,
// and a new SETTINGS_INITIAL_WINDOW_SIZE moves every open stream at once.
type sendView struct {
	init    int64
	streams map[uint32]int64
	frames  []http2.Frame
}

func newSendView() *sendView {
	return &sendView{init: h2InitWindow, streams: map[uint32]int64{}}
}

// receive applies frames the peer read, in order, and keeps them.
func (v *sendView) receive(t testing.TB, b []byte) {
	t.Helper()
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	fr.SetMaxReadFrameSize(1 << 24)
	for {
		frame, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("peer could not read the governor's output: %v", err)
		}
		v.frames = append(v.frames, frame)
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if val, ok := f.Value(http2.SettingInitialWindowSize); ok && !f.IsAck() {
				delta := int64(val) - v.init
				v.init = int64(val)
				for id := range v.streams {
					v.streams[id] += delta
				}
			}
		case *http2.HeadersFrame:
			if _, ok := v.streams[f.StreamID]; !ok {
				v.streams[f.StreamID] = v.init
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID != 0 {
				v.streams[f.StreamID] += int64(f.Increment)
			}
		}
	}
}

// open starts a stream on this peer's own initiative.
func (v *sendView) open(id uint32) {
	v.streams[id] = v.init
}

// pings returns the payloads of the non-ACK PINGs in b.
func pings(t *testing.T, b []byte) [][8]byte {
	t.Helper()
	var out [][8]byte
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	fr.SetMaxReadFrameSize(1 << 24)
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return out
		}
		if p, ok := frame.(*http2.PingFrame); ok && !p.IsAck() {
			out = append(out, p.Data)
		}
	}
}

// queuedBytes is what the governor holds back for the client, as frames.
func queuedBytes(c *flowConn) int {
	return len(c.wqueue) + (h2FrameHeader+4)*len(c.wcredit)
}

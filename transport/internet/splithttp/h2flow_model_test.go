package splithttp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type captureConn struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(b)
}

func (c *captureConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := append([]byte(nil), c.out.Bytes()...)
	c.out.Reset()
	return b
}
func (c *captureConn) Close() error { return nil }

// side is one peer's view of a stream: what it may still receive under its
// own advertised window, what it believes it may send, and what its reader
// has consumed but not yet returned as credit.
type side struct {
	recvAvail int64
	sendView  int64
	buffered  int64
	unsent    int64
	done      bool
}

type modelStream struct {
	client, server   side
	peakUp, peakDown int64
	opened           bool // the server has seen its HEADERS
}

type flowModel struct {
	t        *testing.T
	rnd      *mrand.Rand
	c        *flowConn
	capture  *captureConn
	streams  map[uint32]*modelStream
	next     uint32
	cliInit  int64
	srvInit  int64
	srvPeak  int64 // the largest srvInit so far
	cliSees  int64 // initial window the client believes the server granted
	srvSees  int64 // initial window the server believes the client granted
	up, down flowLimit
	phase    int
	steps    int
	cliConn  int64 // connection window the client believes it has
	srvConn  int64 // connection window the server really has left
	resize   bool  // the client changes its initial window now and then
	changes  int   // mid-connection client window changes applied
	failed   bool  // the governor gave up the connection
	lenient  bool  // do not require a give-up; let the invariants judge

	// proto adds the protocol scenarios of protoStep and checks that every
	// frame the governor does not own reaches the other side as it was sent,
	// see expect and check. clientSide puts a client's governor in the
	// middle instead of a server's.
	proto      bool
	clientSide bool
	toSrv      []rawFrame // frames on their way to the server
	toCli      []rawFrame // frames on their way to the client
	cliBuf     []byte     // what a client's governor passed on to the client
	goaway     bool       // the server sent GOAWAY: no new streams
}

var modelWindows = []int64{h2InitWindow, 128 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20}

func newFlowModel(t *testing.T, seed uint64, up, down flowLimit, frozen bool) *flowModel {
	m := makeFlowModel(t, seed, up, down)
	m.start(frozen)
	return m
}

// makeFlowModel builds a model whose peers have not exchanged the prefaces
// yet, for runs that set it up further first; newFlowModel also starts it.
func makeFlowModel(t *testing.T, seed uint64, up, down flowLimit) *flowModel {
	capture := &captureConn{}
	return &flowModel{
		t: t, rnd: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		c: newFlowConn(capture, up, down), capture: capture,
		streams: map[uint32]*modelStream{}, next: 1,
		cliInit: 0, srvInit: 0,
		cliSees: h2InitWindow, srvSees: h2InitWindow,
		up: up, down: down,
	}
}

// start exchanges the prefaces.
func (m *flowModel) start(frozen bool) {
	m.cliInit = modelWindows[m.rnd.IntN(len(modelWindows))]
	m.srvInit = modelWindows[m.rnd.IntN(len(modelWindows))]
	m.srvPeak = m.srvInit
	m.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(m.cliInit)})
	}, true)
	m.cliConn = h2InitWindow
	connWindow := int64(1 << 20)
	m.srvConn = connWindow
	m.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(m.srvInit)})
		fr.WriteWindowUpdate(0, uint32(connWindow-h2InitWindow))
	})
	m.c.rtt = time.Microsecond
	if frozen {
		m.c.rtt = time.Hour
		m.c.lastPing = time.Now().Add(time.Hour)
	}
}

// fromClient sends frames written by f through the governor towards the
// server and applies whatever reaches the server (and any credit injected
// back to the client) to the model.
func (m *flowModel) fromClient(f func(fr *http2.Framer), preface bool) {
	var b bytes.Buffer
	if preface {
		b.WriteString(h2Preface)
	}
	f(http2.NewFramer(&b, nil))
	in := b.Bytes()
	if m.proto && preface {
		m.expect(&m.toSrv, in[len(h2Preface):])
	} else if m.proto {
		m.expect(&m.toSrv, in)
	}
	piece := m.piece(len(in))
	var toServer []byte
	for len(in) > 0 {
		n := min(len(in), 1+m.rnd.IntN(piece))
		if m.clientSide {
			if _, err := m.c.Write(append([]byte(nil), in[:n]...)); err != nil {
				break
			}
		} else {
			toServer = m.c.readFrames(append([]byte(nil), in[:n]...), toServer)
		}
		in = in[n:]
	}
	if m.clientSide {
		toServer = m.capture.take()
	}
	if preface {
		toServer = toServer[len(h2Preface):]
	}
	m.c.wmu.Lock()
	m.c.wmu.Unlock()
	m.deliverToServer(toServer)
	m.deliverToClient()
}

func (m *flowModel) fromServer(f func(fr *http2.Framer)) {
	var b bytes.Buffer
	f(http2.NewFramer(&b, nil))
	in := b.Bytes()
	if m.proto {
		m.expect(&m.toCli, in)
	}
	piece := m.piece(len(in))
	for len(in) > 0 {
		n := min(len(in), 1+m.rnd.IntN(piece))
		if m.clientSide {
			m.cliBuf = m.c.fromServer(append([]byte(nil), in[:n]...), m.cliBuf)
		} else if _, err := m.c.Write(in[:n]); err != nil {
			if m.proto && errors.Is(err, errFlowGivenUp) {
				m.failed = true
				return
			}
			m.t.Fatal(err)
		}
		in = in[n:]
	}
	m.deliverToClient()
}

// piece is the most fromClient and fromServer hand the governor at once.
// The protocol scenarios at times cut frames into pieces smaller than a
// frame header.
func (m *flowModel) piece(n int) int {
	if m.proto && n < 4<<10 && m.rnd.IntN(4) == 0 {
		return 1 + m.rnd.IntN(16)
	}
	return 2048
}

// toClientBytes takes what reached the client since the last call.
func (m *flowModel) toClientBytes() []byte {
	if !m.clientSide {
		return m.capture.take()
	}
	b := m.cliBuf
	m.cliBuf = nil
	return b
}

func readAll(t *testing.T, b []byte, f func(http2.Frame)) {
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	fr.SetMaxReadFrameSize(1 << 24)
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		f(frame)
	}
}

func (m *flowModel) deliverToServer(b []byte) {
	m.notePeaks()
	if m.proto {
		m.check(&m.toSrv, b, "server")
	}
	m.read(b, func(frame http2.Frame) {
		switch f := frame.(type) {
		case *http2.PingFrame:
			if m.proto && !f.IsAck() {
				data := f.Data
				m.fromServer(func(fr *http2.Framer) { fr.WritePing(true, data) })
			}
		case *http2.SettingsFrame:
			if v, ok := lastInitialWindow(f); ok && !f.IsAck() {
				delta := int64(v) - m.srvSees
				m.srvSees = int64(v)
				for _, s := range m.streams {
					s.server.sendView += delta
				}
			}
		case *http2.HeadersFrame:
			s := m.streams[f.StreamID]
			if s == nil || s.opened {
				return
			}
			s.opened = true
			s.server = side{recvAvail: m.srvInit, sendView: m.srvSees}
		case *http2.DataFrame:
			m.srvConn -= int64(f.Length)
			if m.srvConn < 0 {
				m.t.Fatalf("server received %d bytes beyond its connection window", -m.srvConn)
			}
			s := m.streams[f.StreamID]
			if s == nil {
				m.connCredit(int64(f.Length))
				return
			}
			n := int64(f.Length)
			s.server.recvAvail -= n
			s.server.buffered += n
			// As towards the client: only data that lands beyond a window
			// the server lowered overruns it.
			if n > 0 && s.server.recvAvail < 0 {
				m.t.Fatalf("stream %d: server received %d bytes beyond its window", f.StreamID, -s.server.recvAvail)
			}
			if limit := m.limit(f.StreamID, true); limit > 0 && s.server.buffered > limit+16<<10 {
				m.t.Fatalf("stream %d: %d unread at the server, limit %d", f.StreamID, s.server.buffered, limit)
			}
		case *http2.WindowUpdateFrame:
			if s := m.streams[f.StreamID]; s != nil && f.StreamID != 0 {
				s.server.sendView += int64(f.Increment)
			}
		}
	})
}

func (m *flowModel) deliverToClient() {
	m.notePeaks()
	b := m.toClientBytes()
	if m.proto {
		m.check(&m.toCli, b, "client")
	}
	m.read(b, func(frame http2.Frame) {
		switch f := frame.(type) {
		case *http2.GoAwayFrame:
			m.goAway(f.LastStreamID)
		case *http2.SettingsFrame:
			if v, ok := lastInitialWindow(f); ok && !f.IsAck() {
				delta := int64(v) - m.cliSees
				m.cliSees = int64(v)
				for _, s := range m.streams {
					s.client.sendView += delta
				}
			}
		case *http2.DataFrame:
			s := m.streams[f.StreamID]
			if s == nil {
				return
			}
			n := int64(f.Length)
			s.client.recvAvail -= n
			s.client.buffered += n
			// A window may be negative after the client lowers its initial
			// window; only data that lands there overruns it, not an empty
			// DATA frame that ends the stream.
			if n > 0 && s.client.recvAvail < 0 {
				m.t.Fatalf("stream %d: client received %d bytes beyond its window", f.StreamID, -s.client.recvAvail)
			}
			if limit := m.limit(f.StreamID, false); limit > 0 && s.client.buffered > limit+16<<10 {
				m.t.Fatalf("stream %d: %d unread at the client, limit %d", f.StreamID, s.client.buffered, limit)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				m.cliConn += int64(f.Increment)
			} else if s := m.streams[f.StreamID]; s != nil {
				s.client.sendView += int64(f.Increment)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				m.fromClient(func(fr *http2.Framer) { fr.WritePing(true, data) }, false)
			}
		}
	})
}

// notePeaks records the largest cap each stream has had: a cap shrinks once
// its reader slows down, but what was sent under the larger one may still be
// unread, so that is the bound unread data is held to.
func (m *flowModel) notePeaks() {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	for id, s := range m.streams {
		if st := m.c.streams[id]; st != nil {
			s.peakUp = max(s.peakUp, int64(st.up.cap))
			s.peakDown = max(s.peakDown, int64(st.down.cap))
		}
	}
}

func (m *flowModel) limit(id uint32, up bool) int64 {
	s := m.streams[id]
	switch {
	case s == nil:
		return 0
	case up && m.up.enabled():
		// The client may send the initial window the server shows before
		// the governor holds anything back.
		// Once shown, a larger window may have been sent into before the
		// server lowered it.
		return max(s.peakUp, min(int64(flowShownUp), m.srvPeak))
	case !up && m.down.enabled():
		return s.peakDown
	}
	return 0
}

// consume lets a reader drain up to n buffered bytes and hands credit back
// the way Go's inflow does: once at least 4 KiB is pending, or the pending
// credit would at least double what the peer can still send.
func consume(s *side, n int64) int64 {
	n = min(n, s.buffered)
	s.buffered -= n
	s.unsent += n
	if s.unsent < 4<<10 && s.unsent < s.recvAvail {
		return 0
	}
	credit := s.unsent
	s.recvAvail += credit
	s.unsent = 0
	return credit
}

func (m *flowModel) open() {
	if m.goaway {
		return
	}
	id := m.next
	m.next += 2
	s := &modelStream{client: side{recvAvail: m.cliInit, sendView: m.cliSees}}
	m.streams[id] = s
	if m.proto {
		m.fromClient(func(fr *http2.Framer) { m.writeHeaders(fr, id, false) }, false)
		return
	}
	m.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true})
	}, false)
}

// changeClientWindow announces a new initial window from the client in the
// middle of the connection. Every stream's real window moves with it, and the
// server must end up with no more credit than that on any stream it may still
// send on. Credit the governor already handed out cannot be taken back, so
// the change can only be expressed while no such stream holds more of it
// than the new window covers; otherwise the governor must give up.
func (m *flowModel) changeClientWindow() {
	next := modelWindows[m.rnd.IntN(len(modelWindows))]
	expressible := true
	for _, s := range m.streams {
		// What the governor forwarded beyond what the client returned.
		ahead := s.server.sendView - s.client.recvAvail + m.cliInit - m.srvSees
		if m.down.enabled() && !s.server.done && next < ahead {
			expressible = false
		}
		s.client.recvAvail += next - m.cliInit
	}
	m.cliInit = next
	m.fromClient(func(fr *http2.Framer) {
		if m.proto && m.rnd.IntN(2) == 0 {
			// Only the last value counts; the governor has to show the
			// stack a window no larger in every one.
			fr.WriteSettings(
				http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(modelWindows[m.rnd.IntN(len(modelWindows))])},
				http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 20},
				http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(next)},
			)
			return
		}
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(next)})
	}, false)
	// Adapted to bdbac60e: it has no broken flag; a governor that gives up
	// releases its state, which sets closed.
	m.c.mu.Lock()
	broken := m.c.closed
	m.c.mu.Unlock()
	if m.lenient {
		// Giving up is allowed here, but not required.
		m.failed = broken
		m.changes++
		return
	}
	if broken == expressible {
		m.t.Fatalf("client window to %d: governor gave up %v, change expressible %v", next, broken, expressible)
	}
	m.failed = !expressible
	if expressible {
		m.changes++
	}
}

func (m *flowModel) pick() (uint32, *modelStream) {
	for id, s := range m.streams {
		return id, s
	}
	return 0, nil
}

// step takes one random action. Every few hundred steps the phase changes so
// that one reader stalls for a while and windows run into their edges.
func (m *flowModel) step() {
	m.steps++
	if m.steps%300 == 0 {
		m.phase = m.rnd.IntN(4)
	}
	if m.proto && m.rnd.IntN(4) == 0 {
		m.protoStep()
		return
	}
	id, s := m.pick()
	r := m.rnd.IntN(100)
	if (m.phase == 1 && r >= 30 && r < 45) || (m.phase == 2 && r >= 70 && r < 85) || (m.phase == 3 && (r >= 30 && r < 45 || r >= 70 && r < 85)) {
		r = 26 + 44*m.rnd.IntN(2)
	}
	switch {
	case s == nil || r < 4:
		if len(m.streams) < 8 {
			m.open()
		}
	case r < 30:
		for burst := 1 + m.rnd.IntN(32); burst > 0; burst-- {
			n := min(s.client.sendView, m.cliConn, int64(1+m.rnd.IntN(16384)))
			if n <= 0 || s.client.done {
				break
			}
			s.client.sendView -= n
			m.cliConn -= n
			m.fromClient(func(fr *http2.Framer) { m.writeData(fr, id, n) }, false)
		}
	case r < 45:
		if credit := consume(&s.server, int64(m.rnd.IntN(64<<10))); credit > 0 {
			m.srvConn += credit
			m.fromServer(func(fr *http2.Framer) {
				fr.WriteWindowUpdate(0, uint32(credit))
				fr.WriteWindowUpdate(id, uint32(credit))
			})
		}
	case r < 70:
		if n := min(s.server.sendView, int64(1+m.rnd.IntN(16384))); n > 0 && !s.server.done {
			s.server.sendView -= n
			m.fromServer(func(fr *http2.Framer) { m.writeData(fr, id, n) })
		}
	case r < 85:
		if credit := consume(&s.client, int64(m.rnd.IntN(64<<10))); credit > 0 {
			m.fromClient(func(fr *http2.Framer) {
				fr.WriteWindowUpdate(0, uint32(credit))
				fr.WriteWindowUpdate(id, uint32(credit))
			}, false)
		}
	case r < 88:
		m.fromClient(func(fr *http2.Framer) { fr.WriteRSTStream(id, http2.ErrCodeCancel) }, false)
		m.forget(id)
	case r < 90:
		m.fromServer(func(fr *http2.Framer) { fr.WriteRSTStream(id, http2.ErrCodeCancel) })
		m.forget(id)
	case r < 92:
		s.client.done = true
		m.fromClient(func(fr *http2.Framer) { fr.WriteData(id, true, nil) }, false)
		m.maybeForget(id, s)
	case r < 94:
		s.server.done = true
		m.fromServer(func(fr *http2.Framer) { fr.WriteData(id, true, nil) })
		m.maybeForget(id, s)
	case m.resize && r == 99:
		m.changeClientWindow()
	default:
		m.fromClient(func(fr *http2.Framer) { fr.WritePing(false, modelClientPing) }, false)
		m.fromServer(func(fr *http2.Framer) { fr.WritePing(false, modelServerPing) })
	}
}

func (m *flowModel) maybeForget(id uint32, s *modelStream) {
	if s.client.done && s.server.done {
		m.forget(id)
	}
}

// forget drops a stream the way the Go server closes one: whatever it had
// buffered but not read goes back to the connection window.
func (m *flowModel) forget(id uint32) {
	s := m.streams[id]
	delete(m.streams, id)
	if s != nil {
		m.connCredit(s.server.buffered + s.server.unsent)
	}
}

// connCredit returns connection-level credit from the server, as the Go server
// does for data it will never hand to a handler.
func (m *flowModel) connCredit(n int64) {
	if n <= 0 {
		return
	}
	m.srvConn += n
	m.fromServer(func(fr *http2.Framer) { fr.WriteWindowUpdate(0, uint32(n)) })
}

// drain lets every reader consume everything and checks that each sender that
// still has something to say is then allowed to send.
func (m *flowModel) drain() {
	for round := 0; round < 4; round++ {
		for id, s := range m.streams {
			if credit := consume(&s.server, 1<<40); credit > 0 {
				m.srvConn += credit
				m.fromServer(func(fr *http2.Framer) {
					fr.WriteWindowUpdate(0, uint32(credit))
					fr.WriteWindowUpdate(id, uint32(credit))
				})
			}
			if credit := consume(&s.client, 1<<40); credit > 0 {
				m.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(id, uint32(credit)) }, false)
			}
		}
	}
	pending := int64(0)
	for _, s := range m.streams {
		pending += s.server.buffered + s.server.unsent
	}
	if m.up.enabled() && len(m.streams) > 0 && m.cliConn <= 0 && pending < 4<<10 {
		m.t.Fatalf("client stalled with no connection window after the server drained")
	}
	for id, s := range m.streams {
		if !s.client.done && s.client.sendView <= 0 && s.server.buffered == 0 && s.server.unsent < 4<<10 {
			m.t.Fatalf("stream %d: client stalled with no window after the server drained", id)
		}
		// The stall is the governor's only while the client still allows
		// data: a client that lowered its window below what it holds stalls
		// the stream with stock HTTP/2 too.
		if !s.server.done && s.server.sendView <= 0 && s.client.recvAvail > 0 && s.client.buffered == 0 && s.client.unsent < 4<<10 {
			m.t.Fatalf("stream %d: server stalled with no window after the client drained", id)
		}
	}
}

func TestFlowModelInvariants(t *testing.T) {
	limits := []struct {
		up, down flowLimit
		frozen   bool
	}{
		{testUp, testDown, false},
		{flowLimit{init: h2InitWindow, max: 1 << 20}, flowLimit{init: h2InitWindow, max: 1 << 20}, false},
		{flowLimit{init: 1 << 20, max: 32 << 20}, flowLimit{}, false},
		{flowLimit{}, flowLimit{init: 512 << 10, max: 2 << 20}, false},
		{flowLimit{init: 4 << 20, max: 4 << 20}, flowLimit{}, false},
		{flowLimit{init: 256 << 10, max: 32 << 20}, testDown, true},
	}
	for i, l := range limits {
		t.Run(fmt.Sprintf("limits%d", i), func(t *testing.T) { runModel(t, i, l.up, l.down, l.frozen, false) })
	}
}

// TestFlowModelWindowChanges runs the same model with a client that changes
// its initial window in the middle of the connection.
func TestFlowModelWindowChanges(t *testing.T) {
	for i, l := range []struct{ up, down flowLimit }{
		{testUp, testDown},
		{flowLimit{init: h2InitWindow, max: 1 << 20}, flowLimit{init: h2InitWindow, max: 1 << 20}},
		{flowLimit{init: 1 << 20, max: 32 << 20}, flowLimit{}},
		{flowLimit{}, flowLimit{init: 512 << 10, max: 2 << 20}},
	} {
		t.Run(fmt.Sprintf("limits%d", i), func(t *testing.T) { runModel(t, i, l.up, l.down, false, true) })
	}
}

// TestFlowModelWindowChangesLenient (added for bdbac60e) runs the window-change
// model without requiring the governor to give up an inexpressible change:
// only the stock invariants judge, i.e. the server never sends beyond the
// client's real window and no stream stalls after both readers drain.
func TestFlowModelWindowChangesLenient(t *testing.T) {
	for i, l := range []struct{ up, down flowLimit }{
		{testUp, testDown},
		{flowLimit{init: h2InitWindow, max: 1 << 20}, flowLimit{init: h2InitWindow, max: 1 << 20}},
		{flowLimit{init: 1 << 20, max: 32 << 20}, flowLimit{}},
		{flowLimit{}, flowLimit{init: 512 << 10, max: 2 << 20}},
	} {
		t.Run(fmt.Sprintf("limits%d", i), func(t *testing.T) {
			lenientModel = true
			defer func() { lenientModel = false }()
			runModel(t, i, l.up, l.down, false, true)
		})
	}
}

var lenientModel bool

func runModel(t *testing.T, i int, up, down flowLimit, frozen, resize bool) {
	l := struct {
		up, down flowLimit
		frozen   bool
	}{up, down, frozen}
	{
		seeds := uint64(20)
		if testing.Short() {
			seeds = 8
		}
		changes, failures := 0, 0
		for seed := uint64(0); seed < seeds; seed++ {
			m := newFlowModel(t, seed*97+uint64(i), l.up, l.down, l.frozen)
			m.resize = resize
			m.lenient = lenientModel
			for n := 0; n < 3000 && !m.failed; n++ {
				m.step()
				if n%500 == 499 && !m.failed {
					m.drain()
				}
			}
			changes += m.changes
			if m.failed {
				failures++
				continue
			}
			m.drain()
			m.c.mu.Lock()
			for id := range m.c.streams {
				if _, ok := m.streams[id]; !ok {
					t.Fatalf("limits %d seed %d: governor still tracks finished stream %d", i, seed, id)
				}
			}
			m.c.mu.Unlock()
		}
		if resize {
			if changes == 0 {
				t.Fatalf("limits %d: no client window change was applied in %d seeds", i, seeds)
			}
			t.Logf("limits %d: %d client window changes applied, %d connections given up", i, changes, failures)
		}
	}
}

// rawFrame is a frame as it went over the wire.
type rawFrame struct {
	typ, flags byte
	stream     uint32
	payload    []byte
}

func rawFrames(t testing.TB, b []byte) []rawFrame {
	var fs []rawFrame
	for len(b) > 0 {
		if len(b) < h2FrameHeader {
			t.Fatalf("torn frame header %x", b)
		}
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < h2FrameHeader+n {
			t.Fatalf("torn frame: %d of %d payload bytes", len(b)-h2FrameHeader, n)
		}
		fs = append(fs, rawFrame{b[3], b[4], binary.BigEndian.Uint32(b[5:]), append([]byte(nil), b[h2FrameHeader:h2FrameHeader+n]...)})
		b = b[h2FrameHeader+n:]
	}
	return fs
}

// The data of the PINGs the model's client and server send.
var modelClientPing, modelServerPing = [8]byte{1}, [8]byte{2}

// modelPing tells the PINGs of the model's peers from the governor's own.
func modelPing(data []byte) bool {
	return bytes.Equal(data, modelClientPing[:]) || bytes.Equal(data, modelServerPing[:])
}

// expect notes the frames in b a peer sent: all but WINDOW_UPDATE, whose
// credit the governor owns, and the ACKs of the governor's PINGs, which it
// takes, have to reach the other side as they are, as without the governor.
func (m *flowModel) expect(q *[]rawFrame, b []byte) {
	for _, f := range rawFrames(m.t, b) {
		if f.typ == h2WindowUpdate || f.typ == h2Ping && f.flags&h2FlagAck != 0 && !modelPing(f.payload) {
			continue
		}
		*q = append(*q, f)
	}
}

// check takes the frames in b, on their way to the named side, off q in the
// order they were sent. The governor may add WINDOW_UPDATE and its own PINGs,
// lower the initial window and cap the frame size in SETTINGS, and nothing
// else.
func (m *flowModel) check(q *[]rawFrame, b []byte, to string) {
	m.c.mu.Lock()
	broken := m.c.broken
	m.c.mu.Unlock()
	if broken {
		*q = nil
		return
	}
	for _, got := range rawFrames(m.t, b) {
		if got.typ == h2WindowUpdate {
			continue
		}
		if got.typ == h2Ping && got.flags == 0 && !modelPing(got.payload) {
			if got.stream != 0 || len(got.payload) != 8 {
				m.t.Fatalf("to the %s: malformed PING %+v", to, got)
			}
			continue
		}
		if len(*q) == 0 {
			m.t.Fatalf("to the %s: frame %+v that nobody sent", to, got)
		}
		want := (*q)[0]
		*q = (*q)[1:]
		if !sameFrame(want, got) {
			m.t.Fatalf("to the %s: sent %+v, got %+v", to, want, got)
		}
	}
	if len(*q) > 0 {
		m.t.Fatalf("to the %s: %d frames lost, first %+v", to, len(*q), (*q)[0])
	}
}

func sameFrame(want, got rawFrame) bool {
	if want.typ != got.typ || want.flags != got.flags || want.stream != got.stream || len(want.payload) != len(got.payload) {
		return false
	}
	if want.typ != h2Settings || want.flags&h2FlagAck != 0 {
		return bytes.Equal(want.payload, got.payload)
	}
	for i := 0; i+6 <= len(want.payload); i += 6 {
		id, w, g := binary.BigEndian.Uint16(want.payload[i:]), binary.BigEndian.Uint32(want.payload[i+2:]), binary.BigEndian.Uint32(got.payload[i+2:])
		switch {
		case id != binary.BigEndian.Uint16(got.payload[i:]):
			return false
		case id == h2SettingInitialWindowSize && g > w,
			id == h2SettingMaxFrameSize && g != min(w, h2MinMaxFrameSize),
			id != h2SettingInitialWindowSize && id != h2SettingMaxFrameSize && g != w:
			return false
		}
	}
	return true
}

// read is readAll that, with the protocol scenarios, takes any frame the
// stock framer rejects as a failure rather than the end of the input.
func (m *flowModel) read(b []byte, f func(http2.Frame)) {
	if !m.proto {
		readAll(m.t, b, f)
		return
	}
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	fr.SetMaxReadFrameSize(1 << 24)
	for {
		frame, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			m.t.Fatalf("stock framer rejects the governor's output: %v", err)
		}
		f(frame)
	}
}

// lastInitialWindow is the initial window a SETTINGS frame leaves: the last
// one in it, as the stock stack applies them in order.
func lastInitialWindow(f *http2.SettingsFrame) (v uint32, ok bool) {
	f.ForeachSetting(func(s http2.Setting) error {
		if s.ID == http2.SettingInitialWindowSize {
			v, ok = s.Val, true
		}
		return nil
	})
	return v, ok
}

// modelPool is the data DATA frames carry, so that bytes the governor mixed
// up would show.
var modelPool = func() []byte {
	b := make([]byte, 64<<10)
	r := mrand.New(mrand.NewPCG(1, 2))
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}()

// writeData writes n bytes of flow-controlled DATA on id: with the protocol
// scenarios at times padded, which counts against the window like data.
func (m *flowModel) writeData(fr *http2.Framer, id uint32, n int64) {
	if !m.proto {
		fr.WriteData(id, false, make([]byte, n))
		return
	}
	off := m.rnd.IntN(len(modelPool) - int(n))
	if pad := int64(m.rnd.IntN(256)); m.rnd.IntN(3) == 0 && n > pad {
		fr.WriteDataPadded(id, false, modelPool[off:off+int(n-1-pad)], make([]byte, pad))
		return
	}
	fr.WriteData(id, false, modelPool[off:off+int(n)])
}

// writeHeaders writes a header block on id, at times cut into HEADERS and
// CONTINUATION frames.
func (m *flowModel) writeHeaders(fr *http2.Framer, id uint32, end bool) {
	off := m.rnd.IntN(len(modelPool) - 3*h2MinMaxFrameSize)
	block := modelPool[off : off+1+m.rnd.IntN(3*h2MinMaxFrameSize)]
	first := min(len(block), 1+m.rnd.IntN(h2MinMaxFrameSize))
	if m.rnd.IntN(2) == 0 {
		first = len(block)
	}
	first = min(first, h2MinMaxFrameSize)
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:first], EndStream: end, EndHeaders: first == len(block)})
	for block = block[first:]; len(block) > 0; {
		n := min(len(block), 1+m.rnd.IntN(h2MinMaxFrameSize))
		fr.WriteContinuation(id, n == len(block), block[:n])
		block = block[n:]
	}
}

// goAway follows a GOAWAY at the client: like a Go client, it resets the
// streams the server will not process.
func (m *flowModel) goAway(last uint32) {
	m.goaway = true
	for id := range m.streams {
		if id > last {
			m.fromClient(func(fr *http2.Framer) { fr.WriteRSTStream(id, http2.ErrCodeRefusedStream) }, false)
			m.forget(id)
		}
	}
}

// changeServerWindow announces a new initial window from the server in the
// middle of the connection. The governor may give up where its credit cannot
// be taken back; otherwise the invariants judge.
func (m *flowModel) changeServerWindow() {
	next := modelWindows[m.rnd.IntN(len(modelWindows))]
	for _, s := range m.streams {
		s.server.recvAvail += next - m.srvInit
	}
	m.srvInit, m.srvPeak = next, max(m.srvPeak, next)
	m.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(next)})
	})
	m.c.mu.Lock()
	m.failed = m.failed || m.c.broken
	m.c.mu.Unlock()
}

// protoStep takes one action of the protocol scenarios: header blocks cut
// into CONTINUATION, trailers, responses without a body, SETTINGS the
// governor rewrites and ones it leaves alone, ACKs, frames of unknown type,
// PRIORITY, and GOAWAY.
func (m *flowModel) protoStep() {
	id, s := m.pick()
	r := m.rnd.IntN(100)
	switch {
	case s == nil:
		m.open()
	case r < 10 && !s.client.done:
		s.client.done = true
		m.fromClient(func(fr *http2.Framer) { m.writeHeaders(fr, id, true) }, false)
		m.maybeForget(id, s)
	case r < 20 && !s.server.done:
		s.server.done = true
		m.fromServer(func(fr *http2.Framer) { m.writeHeaders(fr, id, true) })
		m.maybeForget(id, s)
	case r < 30 && !s.server.done:
		m.fromServer(func(fr *http2.Framer) { m.writeHeaders(fr, id, false) })
	case r < 40:
		m.fromClient(func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 1 << 12}, http2.Setting{ID: http2.SettingMaxFrameSize, Val: uint32(h2MinMaxFrameSize << m.rnd.IntN(8))})
			fr.WriteSettingsAck()
		}, false)
	case r < 50:
		m.fromServer(func(fr *http2.Framer) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100}, http2.Setting{ID: http2.SettingMaxFrameSize, Val: uint32(h2MinMaxFrameSize << m.rnd.IntN(8))})
			fr.WriteSettingsAck()
		})
	case r < 60:
		stream := id
		if m.rnd.IntN(2) == 0 {
			stream = 0
		}
		payload := modelPool[:m.rnd.IntN(64)]
		if m.rnd.IntN(2) == 0 {
			m.fromClient(func(fr *http2.Framer) { fr.WriteRawFrame(http2.FrameType(0x20+m.rnd.IntN(16)), 0, stream, payload) }, false)
		} else {
			m.fromServer(func(fr *http2.Framer) { fr.WriteRawFrame(http2.FrameType(0x20+m.rnd.IntN(16)), 0, stream, payload) })
		}
	case r < 70:
		m.fromClient(func(fr *http2.Framer) {
			fr.WritePriority(id, http2.PriorityParam{Weight: uint8(m.rnd.IntN(256))})
		}, false)
	case r < 78:
		m.fromClient(func(fr *http2.Framer) { fr.WritePing(false, modelClientPing) }, false)
	case r < 86:
		m.fromServer(func(fr *http2.Framer) { fr.WritePing(false, modelServerPing) })
	case r < 92 && !m.clientSide:
		m.changeServerWindow()
	case r < 94 && !m.goaway && m.steps > 2500:
		// The server stops taking new streams. At times the last ones
		// were still on their way and are refused.
		last := m.next - 2
		if n := 2 * uint32(m.rnd.IntN(3)); n < last {
			last -= n
		}
		m.fromServer(func(fr *http2.Framer) { fr.WriteGoAway(last, http2.ErrCodeNo, nil) })
	}
}

// TestFlowModelProtocol runs the model with the protocol scenarios on both
// a server's and a client's governor, with and without a send window, and
// with a client that changes its initial window: every frame not about flow
// control has to arrive as it was sent, the governor off being the identity,
// and no peer may see more window than the other granted.
func TestFlowModelProtocol(t *testing.T) {
	seeds := uint64(12)
	if testing.Short() {
		seeds = 4
	}
	for i, l := range []struct {
		up, down   flowLimit
		client     bool
		sendWindow int64
		resize     bool
	}{
		{testUp, testDown, false, 0, false},
		{testUp, testDown, false, 4 << 20, false},
		{testUp, testDown, false, 0, true},
		{testUp, testDown, false, 1 << 20, true},
		{flowLimit{}, flowLimit{}, false, 0, false},
		{flowLimit{}, testDown, true, 0, false},
		{flowLimit{}, testDown, true, 0, true},
	} {
		t.Run(fmt.Sprintf("limits%d", i), func(t *testing.T) {
			for seed := uint64(0); seed < seeds; seed++ {
				runProtoModel(t, seed*131+uint64(i), l.up, l.down, l.client, l.sendWindow, l.resize)
			}
		})
	}
}

func runProtoModel(t *testing.T, seed uint64, up, down flowLimit, client bool, sendWindow int64, resize bool) {
	m := makeFlowModel(t, seed, up, down)
	m.proto, m.clientSide, m.resize = true, client, resize
	m.c.client, m.c.sendWindow = client, sendWindow
	m.start(false)
	for n := 0; n < 3000 && !m.failed; n++ {
		m.step()
		if n%500 == 499 && !m.failed {
			m.drain()
		}
	}
	if m.failed {
		return
	}
	m.drain()
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	for id := range m.c.streams {
		if _, ok := m.streams[id]; !ok {
			t.Fatalf("seed %d: governor still tracks finished stream %d", seed, id)
		}
	}
}

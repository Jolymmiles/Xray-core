package splithttp

import (
	"bytes"
	"fmt"
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
	cliSees  int64 // initial window the client believes the server granted
	srvSees  int64 // initial window the server believes the client granted
	up, down flowLimit
	phase    int
	steps    int
	cliConn  int64 // connection window the client believes it has
	srvConn  int64 // connection window the server really has left
}

func newFlowModel(t *testing.T, seed uint64, up, down flowLimit, frozen bool) *flowModel {
	capture := &captureConn{}
	m := &flowModel{
		t: t, rnd: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		c: newFlowConn(capture, up, down), capture: capture,
		streams: map[uint32]*modelStream{}, next: 1,
		cliInit: 0, srvInit: 0,
		cliSees: h2InitWindow, srvSees: h2InitWindow,
		up: up, down: down,
	}
	sizes := []int64{h2InitWindow, 128 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20}
	m.cliInit = sizes[m.rnd.IntN(len(sizes))]
	m.srvInit = sizes[m.rnd.IntN(len(sizes))]
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
	return m
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
	var toServer []byte
	for len(in) > 0 {
		n := min(len(in), 1+m.rnd.IntN(2048))
		toServer = m.c.readFrames(append([]byte(nil), in[:n]...), toServer)
		in = in[n:]
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
	for len(in) > 0 {
		n := min(len(in), 1+m.rnd.IntN(2048))
		if _, err := m.c.Write(in[:n]); err != nil {
			m.t.Fatal(err)
		}
		in = in[n:]
	}
	m.deliverToClient()
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
	readAll(m.t, b, func(frame http2.Frame) {
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok && !f.IsAck() {
				delta := int64(v) - m.srvSees
				m.srvSees = int64(v)
				for _, s := range m.streams {
					s.server.sendView += delta
				}
			}
		case *http2.HeadersFrame:
			s := m.streams[f.StreamID]
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
			if s.server.recvAvail < 0 {
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
	b := m.capture.take()
	readAll(m.t, b, func(frame http2.Frame) {
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok && !f.IsAck() {
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
			if s.client.recvAvail < 0 {
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
		return s.peakUp
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
	id := m.next
	m.next += 2
	s := &modelStream{client: side{recvAvail: m.cliInit, sendView: m.cliSees}}
	m.streams[id] = s
	m.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true})
	}, false)
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
			m.fromClient(func(fr *http2.Framer) { fr.WriteData(id, false, make([]byte, n)) }, false)
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
			m.fromServer(func(fr *http2.Framer) { fr.WriteData(id, false, make([]byte, n)) })
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
	default:
		m.fromClient(func(fr *http2.Framer) { fr.WritePing(false, [8]byte{1}) }, false)
		m.fromServer(func(fr *http2.Framer) { fr.WritePing(false, [8]byte{2}) })
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
		if !s.server.done && s.server.sendView <= 0 && s.client.buffered == 0 && s.client.unsent < 4<<10 {
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
		t.Run(fmt.Sprintf("limits%d", i), func(t *testing.T) { runModel(t, i, l.up, l.down, l.frozen) })
	}
}

func runModel(t *testing.T, i int, up, down flowLimit, frozen bool) {
	l := struct {
		up, down flowLimit
		frozen   bool
	}{up, down, frozen}
	{
		seeds := uint64(20)
		if testing.Short() {
			seeds = 8
		}
		for seed := uint64(0); seed < seeds; seed++ {
			m := newFlowModel(t, seed*97+uint64(i), l.up, l.down, l.frozen)
			for n := 0; n < 3000; n++ {
				m.step()
				if n%500 == 499 {
					m.drain()
				}
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
	}
}

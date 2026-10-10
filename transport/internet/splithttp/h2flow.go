package splithttp

import (
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/net/http2"
)

// flowConn sits between a TLS/REALITY connection and the local HTTP/2 stack.
// It rewrites HTTP/2 flow control so that nothing buffers more than its reader
// has recently shown it can consume, the way TCP autotuning does:
//   - uplink: the client is shown a small initial window and gets credit only
//     as the handler reads, capped at twice what the handler read per RTT;
//   - downlink: the server is shown a small client window and gets the
//     client's credit back only while unread data at the client stays under
//     twice what the client read per RTT.
// On a server both apply; on a client only the downlink does, since that is
// the only side of the exchange whose buffers are local. Neither peer needs to
// know: each only ever sees a window no larger than the other side granted.

const (
	h2Preface     = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2FrameHeader = 9
	h2InitWindow  = 65535
	h2MaxWindow   = 1<<31 - 1

	h2Data         = 0x0
	h2Headers      = 0x1
	h2RSTStream    = 0x3
	h2Settings     = 0x4
	h2PushPromise  = 0x5
	h2Ping         = 0x6
	h2WindowUpdate = 0x8
	h2Continuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4

	h2SettingInitialWindowSize = 0x4
	h2SettingMaxFrameSize      = 0x5
	h2MinMaxFrameSize          = 16384

	flowPingSlots    = 4
	flowPingInterval = time.Second
	flowPingTimeout  = 10 * time.Second
	flowDefaultRTT   = 200 * time.Millisecond
	flowRTTWindow    = 10 * time.Second
	flowMinRTT       = time.Millisecond
	flowLearnHalf    = time.Minute
	flowStartWindow  = 256 << 10
	// flowMaxStreams bounds the streams one connection makes the governor
	// track; stock HTTP/2 refuses far fewer concurrent ones.
	flowMaxStreams = 4096
	// flowConnFloor is the connection window a governed receiver shows
	// before its readers prove they need more: Go's default.
	flowConnFloor   = 1 << 20
	flowSmallCredit = 64 << 10
	// Credit is handed on in pieces of at least flowQuantumMin and at most
	// flowQuantumMax where the sender is not about to run dry, see hold. The
	// larger stays under flowSmallCredit, so a governor at the other end
	// still sees a peer that credits in small steps.
	flowQuantumMin = 16 << 10
	flowQuantumMax = 32 << 10
	// flowPingRecheck is how many frame boundaries pass between looks at
	// the clock on a connection that needs no PING.
	flowPingRecheck = 64
	flowShrinkAfter = 3
	flowKernelEvery = 20 * time.Millisecond
	flowQueueHold   = 15 * time.Millisecond
	flowQueueShrink = 40 * time.Millisecond

	flowUndecided = 0
	flowH2        = 1
	flowPlain     = 2
)

type flowLimit struct {
	init, max int32
}

func (l flowLimit) enabled() bool {
	return l.max > 0
}

// flowEnabled is the default for XHTTP connections whose "h2Flow" does not
// say: off unless XRAY_XHTTP_FLOW=on.
var flowEnabled = platform.NewEnvFlag(platform.XHTTPFlow).GetValue(func() string { return "" }) == "on"

// flowDefault never lets a window shrink below the initial window HTTP/2
// itself defines, nor grow beyond what the peer really granted.
var flowDefault = flowLimit{init: h2InitWindow, max: 1 << 30}

// The initial window each side is shown, where the receiver grants that
// much. A server shows Go's own 1 MiB, so its SETTINGS carry the stock value
// and new upload streams need no credit at once; the upload connection
// window still holds everything nobody reads to 1 MiB. A client keeps the
// protocol default: when both ends govern the download, a larger value lets
// the two hold back credit each counts as the other's, and a duplex stream
// can stall.
const (
	flowShownUp   = 1 << 20
	flowShownDown = h2InitWindow
)

type tcpStats struct {
	rtt, minRTT, rttVar time.Duration
}

type flowListener struct {
	net.Listener
	up, down flowLimit
	// connWindow is the connection receive window the local server grants.
	connWindow int32
	// sendWindow is what one connection's client may hold in all, 0 for no
	// limit, see flowConn.downRelease.
	sendWindow int64
}

func (l *flowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	fc := newFlowConn(c, l.up, l.down)
	fc.sendWindow = l.sendWindow
	if l.connWindow > 0 {
		fc.upConnGrant, fc.upConnGrantKnown = int64(max(l.connWindow, h2InitWindow)-h2InitWindow), true
	}
	return fc.wrap(), nil
}

// flowTLSConn is the governor over a TLS connection. It shows net/http the
// TLS state and handshake, so the server treats it as TLS exactly as it would
// the bare connection: it answers plaintext probes, picks the protocol by
// ALPN and sends its SETTINGS before the client preface.
type flowTLSConn struct {
	*flowConn
}

func (c flowTLSConn) ConnectionState() gotls.ConnectionState {
	return c.tlsConn.ConnectionState()
}

func (c flowTLSConn) HandshakeContext(ctx context.Context) error {
	err := c.tlsConn.HandshakeContext(ctx)
	c.followALPN()
	return err
}

// wrap returns c as net/http should see it: with the TLS interfaces where
// the connection under it is TLS.
func (c *flowConn) wrap() net.Conn {
	if tc, ok := c.Conn.(*gotls.Conn); ok {
		c.tlsConn = tc
		return flowTLSConn{c}
	}
	return c
}

// followALPN settles the mode of a TLS connection once its handshake is
// done, as net/http does: HTTP/2 only where ALPN picked h2, so the server's
// SETTINGS, written before the client preface, are governed, and anything
// else passes untouched even if it looks like a preface.
func (c *flowConn) followALPN() {
	if c.tlsConn == nil || c.alpnDone.Load() {
		return
	}
	st := c.tlsConn.ConnectionState()
	if !st.HandshakeComplete {
		return
	}
	if st.NegotiatedProtocol == "h2" {
		c.alpnH2.Store(true)
	} else {
		c.mode.Store(flowPlain)
	}
	c.alpnDone.Store(true)
}

// CloseWrite lets net/http end the stream after an error response at once,
// as it does on the bare connection.
func (c *flowConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type h2Frame struct {
	typ, flags byte
	stream     uint32
	length     int
}

// control reports whether the governor inspects f. Anything malformed by the
// stock rules, such as SETTINGS or PING off stream 0, passes on byte for
// byte, so the receiving stack fails it as it would without the governor.
func (f h2Frame) control() bool {
	switch f.typ {
	case h2Settings:
		return f.stream == 0 && f.length%6 == 0 && f.length <= h2MinMaxFrameSize
	case h2Ping:
		return f.stream == 0 && f.length == 8
	case h2WindowUpdate:
		return f.length == 4
	}
	return false
}

// validSettings reports whether every value in a SETTINGS payload is one the
// stock HTTP/2 stack accepts.
func validSettings(payload []byte) bool {
	for i := 0; i+6 <= len(payload); i += 6 {
		s := http2.Setting{ID: http2.SettingID(binary.BigEndian.Uint16(payload[i:])), Val: binary.BigEndian.Uint32(payload[i+2:])}
		if s.Valid() != nil {
			return false
		}
	}
	return true
}

type frameHandler interface {
	frame(f h2Frame)
	control(f h2Frame, header, payload, out []byte) []byte
	boundary(out []byte) []byte
}

type frameParser struct {
	f       h2Frame
	hdr     [h2FrameHeader]byte
	hdrLen  int
	ctrl    []byte
	remain  int
	collect bool
	inBlock bool
}

func (p *frameParser) atBoundary() bool {
	return p.hdrLen == 0 && p.remain == 0 && !p.collect && !p.inBlock
}

func (p *frameParser) feed(in, out []byte, h frameHandler) []byte {
	for len(in) > 0 {
		switch {
		case p.remain > 0:
			n := min(p.remain, len(in))
			out = append(out, in[:n]...)
			in, p.remain = in[n:], p.remain-n
			if p.remain == 0 {
				out = p.done(out, h)
			}
		case p.collect:
			n := min(p.f.length-len(p.ctrl), len(in))
			p.ctrl = append(p.ctrl, in[:n]...)
			in = in[n:]
			if len(p.ctrl) == p.f.length {
				out = p.finishControl(out, h)
			}
		default:
			n := copy(p.hdr[p.hdrLen:], in)
			p.hdrLen += n
			in = in[n:]
			if p.hdrLen < h2FrameHeader {
				continue
			}
			p.hdrLen = 0
			p.f = h2Frame{
				typ:    p.hdr[3],
				flags:  p.hdr[4],
				stream: binary.BigEndian.Uint32(p.hdr[5:]) & 0x7fffffff,
				length: int(p.hdr[0])<<16 | int(p.hdr[1])<<8 | int(p.hdr[2]),
			}
			// Inside a header block nothing but CONTINUATION may come;
			// whatever does passes on unread for the stack to reject.
			if !p.inBlock && p.f.control() {
				p.collect = true
				if p.f.length == 0 {
					out = p.finishControl(out, h)
				}
				continue
			}
			h.frame(p.f)
			out = append(out, p.hdr[:]...)
			p.remain = p.f.length
			if p.remain == 0 {
				out = p.done(out, h)
			}
		}
	}
	return out
}

func (p *frameParser) finishControl(out []byte, h frameHandler) []byte {
	out = h.control(p.f, p.hdr[:], p.ctrl, out)
	p.ctrl = p.ctrl[:0]
	p.collect = false
	return p.done(out, h)
}

func (p *frameParser) done(out []byte, h frameHandler) []byte {
	switch p.f.typ {
	case h2Headers, h2PushPromise, h2Continuation:
		p.inBlock = p.f.flags&h2FlagEndHeaders == 0
	}
	if p.inBlock {
		return out
	}
	return h.boundary(out)
}

type flowWindow struct {
	cap      int32
	returned int64
	mark     time.Time
	markBase int64
	slow     int
	waiting  time.Time
	prev     int64
	measured bool
	ramped   bool
	qAt      time.Time
	qSample  int
	rates    [flowModelRounds]int64
	rateAt   int
	flat     int
	piPrev   float64
}

// adjust sets the cap to twice what the reader consumed over the last round
// trip: at once when that is more, and by a quarter at a time, never below
// init, once the reader has kept well under it for flowShrinkAfter round trips.
// Until the first round trip is measured the cap opens with every credit, and
// while the reader keeps speeding up it also covers the sender doubling its
// rate, as Linux receive autotuning does. hold keeps the cap from growing.
func (w *flowWindow) adjust(now time.Time, rtt time.Duration, init, limit int32, shrink, hold bool) {
	if w.mark.IsZero() {
		w.mark, w.markBase = now, w.returned
		return
	}
	if !w.measured && !hold {
		if open := int64(init) + 2*w.returned; open > int64(w.cap) {
			w.cap = int32(min(open, int64(limit)))
		}
	}
	if now.Sub(w.mark) < rtt {
		return
	}
	copied := w.returned - w.markBase
	s := 2 * copied
	grow := s
	if w.prev > 0 && copied <= w.prev {
		w.ramped = true
	}
	if !w.ramped && w.prev > 0 {
		grow += 2 * s * (copied - w.prev) / w.prev
	}
	if hold {
		grow = min(grow, int64(w.cap))
	}
	if w.prev > 0 && 4*copied < 5*w.prev {
		w.flat++
	} else {
		w.flat = 0
	}
	w.prev, w.measured = copied, true
	w.mark, w.markBase = now, w.returned
	switch {
	case grow > int64(w.cap):
		w.cap = int32(min(grow, int64(limit)))
		w.slow = 0
	case shrink && 2*s < int64(w.cap):
		if w.slow++; w.slow >= flowShrinkAfter {
			w.cap = int32(max(int64(init), s, int64(w.cap)*3/4))
			w.slow = 0
		}
	default:
		w.slow = 0
	}
}

// Once the kernel vouches for the round trip of the empty path, a ramped
// window follows a model of the path instead of reacting to queueing: the
// bandwidth-delay product BBR would estimate, from the fastest the reader took
// data over the last flowModelRounds round trips, plus a quarter. The quarter
// lets the reader's rate rise by as much per round trip where there is room,
// and leaves at most a quarter round trip of queue where there is not.
const (
	flowModelRounds      = 10
	flowModelGainPercent = 125
	flowModelMinRound    = 20 * time.Millisecond
)

// model sets the cap from the path model; rtprop is the empty path's round
// trip.
func (w *flowWindow) model(now time.Time, rtprop time.Duration, init, limit int32) {
	round := max(rtprop, flowModelMinRound)
	if w.rateAt == 0 && w.prev > 0 {
		// The ramp's last round seeds the filter, so one slow first round
		// cannot drop a window the reader just showed it fills.
		w.rates[0] = w.prev * int64(time.Second) / int64(round)
		w.rateAt = 1
	}
	if now.Sub(w.mark) < round {
		return
	}
	w.rates[w.rateAt%flowModelRounds] = (w.returned - w.markBase) * int64(time.Second) / int64(now.Sub(w.mark))
	w.rateAt++
	w.mark, w.markBase = now, w.returned
	var bw int64
	for _, r := range w.rates {
		bw = max(bw, r)
	}
	target := bw * int64(rtprop) / int64(time.Second) * flowModelGainPercent / 100
	w.cap = int32(min(max(target, int64(init)), int64(limit)))
}

// Once the reader's rate has grown by less than a quarter for flowFullRounds
// round trips in a row, the path is full, as BBR judges it, and a download
// window on a server is held by a PI controller on the queue the kernel sees.
// The error is a fraction of the setpoint and a step a fraction of the bytes
// the setpoint holds at the reader's rate, once per round trip, so the loop
// gain is the controller's own and the same gains fit any bandwidth and RTT.
const (
	flowFullRounds = 3
	flowPIKi       = 0.3
	flowPIKp       = 0.2
	flowPIMaxStep  = 0.5
	flowPIMinSet   = 5 * time.Millisecond
)

// pi moves the cap once per round trip so that the queue settles at a quarter
// of the empty path's round trip, or at four times the RTT variance where the
// path jitters more: the floor is the lowest sample ever, deep in the jitter's
// tail, while the smoothed RTT sits at its middle, and that gap is no queue. In velocity form it adds Ki
// times the error and Kp times its change. With the queue under a quarter of
// the setpoint the cap may also grow by a quarter per round trip, so that it
// catches up with a path that got faster. A reader that takes less than a
// quarter of the window per round trip limits itself: the cap does not grow
// then, and shrinks by a quarter after flowShrinkAfter such rounds.
func (w *flowWindow) pi(now time.Time, st tcpStats, init, limit int32) {
	round := now.Sub(w.mark)
	if round < max(st.minRTT, flowModelMinRound) {
		return
	}
	copied := w.returned - w.markBase
	w.mark, w.markBase = now, w.returned
	set := max(st.minRTT/4, 4*st.rttVar, flowPIMinSet)
	e := min(max(float64(set-(st.rtt-st.minRTT))/float64(set), -2), 1)
	held := float64(copied) * float64(set) / float64(round)
	delta := held * (flowPIKi*e + flowPIKp*(e-w.piPrev))
	w.piPrev = e
	cap := float64(w.cap)
	if e > 0.75 {
		delta = max(delta, cap/4)
	}
	delta = min(max(delta, -flowPIMaxStep*cap), flowPIMaxStep*cap)
	if 4*copied < int64(w.cap) {
		delta = min(delta, 0)
		if w.slow++; w.slow >= flowShrinkAfter {
			delta = min(delta, -cap/4)
			w.slow = 0
		}
	} else {
		w.slow = 0
	}
	w.cap = int32(min(max(int64(cap+delta), int64(init)), int64(limit)))
}

// flowLearned remembers the largest cap a stream on this connection needed
// recently, so short-lived streams (packet-up POSTs) start where the last one
// left off. It halves every flowLearnHalf, so a fast session on a pooled
// connection does not hand its window to every session after it.
type flowLearned struct {
	cap int32
	at  time.Time
}

func (l *flowLearned) value(now time.Time, init int32) int32 {
	if l.cap <= init {
		return init
	}
	halves := now.Sub(l.at) / flowLearnHalf
	if halves >= 31 {
		return init
	}
	return init + (l.cap-init)>>halves
}

func (l *flowLearned) note(now time.Time, init, cap int32) {
	if cap > l.value(now, init) {
		l.cap, l.at = cap, now
	}
}

type flowStream struct {
	up, down      flowWindow
	upSent        int64
	upForwarded   int64
	downSent      int64
	downForwarded int64
	clientDone    bool
	serverDone    bool
}

type flowConn struct {
	net.Conn
	up, down flowLimit
	client   bool
	mode     atomic.Int32
	// tlsConn is the TLS connection under the governor, if any; alpnH2
	// says its ALPN picked h2 before the client preface was seen.
	tlsConn  *gotls.Conn
	alpnH2   atomic.Bool
	alpnDone atomic.Bool

	mu          sync.Mutex
	streams     map[uint32]*flowStream
	upLearned   flowLearned
	downLearned flowLearned
	clientInit  int32
	clientShown int32
	serverInit  int32
	serverShown int32
	rtt         time.Duration
	rttPrev     time.Duration
	rttSince    time.Time
	rttLast     time.Duration
	rttBase     time.Duration
	rttSamples  int
	pingData    uint64
	pings       []flowPing
	pingSentAt  time.Time
	lastPing    time.Time

	incremental bool
	guard       *time.Timer
	guardProbe  bool

	rp       frameParser
	rpending []byte
	prefix   int
	opened   []uint32

	wmu          sync.Mutex
	wp           frameParser
	wqueue       []byte
	wcredit      map[uint32]int64
	wpending     atomic.Bool
	settingsSent bool
	pingReady    bool
	pingSkip     int
	closed       bool
	broken       bool

	// Connection-level window of the upload: DATA the client sent, credit
	// the server returned on stream 0, and credit handed on to the client.
	upConnSent      int64
	upConnReturned  int64
	upConnForwarded int64
	// upConnGrant is the connection window the server grants on top of the
	// protocol's 65535: its first stream-0 credit, the rest of which is data
	// a handler read. The listener knows it; without one it is the credit
	// seen before any DATA.
	upConnGrant      int64
	upConnGrantKnown bool

	// sendWindow is what this connection's client may hold in all, 0 for no
	// limit, see downRelease.
	sendWindow int64

	tcp   syscall.RawConn
	kstat tcpStats
	kAt   time.Time
	kOK   bool
}

// queueing tells how far the kernel RTT of this TCP connection has climbed
// above its own floor: 1 means a queue is building and download windows
// should not grow, 2 means they should shrink, because more data in flight
// would only wait in that queue. It compares the socket only with itself, so
// a TCP proxy in front leaves it quiet; the round trip the windows grow by
// still comes from the PING, which crosses such a proxy.
func (c *flowConn) queueing(now time.Time) int {
	if !c.kernelStats(now) {
		return 0
	}
	switch q := c.kstat.rtt - c.kstat.minRTT; {
	case q > max(2*c.kstat.minRTT, flowQueueShrink):
		return 2
	case q > max(c.kstat.minRTT, flowQueueHold):
		return 1
	}
	return 0
}

// kernelStats refreshes the kernel's view of this TCP connection and reports
// whether there is one.
func (c *flowConn) kernelStats(now time.Time) bool {
	if c.tcp == nil {
		return false
	}
	if now.Sub(c.kAt) >= flowKernelEvery {
		c.kAt = now
		c.kstat, c.kOK = readTCPStats(c.tcp)
	}
	return c.kOK && c.kstat.minRTT > 0
}

// pingFloor is the round trip of the empty path for pingQueueing. The first
// PING's ACK can already wait behind data the peer pushed while its TCP was
// still in slow start, so the kernel's min_rtt, taken at the TCP handshake,
// is preferred. A TCP proxy in front shows the kernel only the hop to the
// proxy: a min_rtt that far below the PING's means exactly that, and the PING
// is kept.
func (c *flowConn) pingFloor(now time.Time) time.Duration {
	floor := c.rttBase
	if c.floorConfirmed(now) && c.kstat.minRTT < floor {
		floor = c.kstat.minRTT
	}
	return floor
}

// modelled reports whether windows follow the path model: the kernel vouches
// for the round trip, as checked against the first PING.
func (c *flowConn) modelled(now time.Time) bool {
	return c.rttBase != 0 && c.floorConfirmed(now)
}

// floorConfirmed reports whether the kernel vouches for the round trip of the
// empty path: it has a min_rtt for this socket that is not far below what the
// PINGs show, so no TCP proxy sits in front.
func (c *flowConn) floorConfirmed(now time.Time) bool {
	return c.kernelStats(now) && (c.rttBase == 0 || 4*c.kstat.minRTT >= c.rttBase)
}

// Without a confirmed floor the PING-seen queue cannot be told from the round
// trip, so windows that the queue hold guards stay where Go keeps them.
const (
	flowUnconfirmedUp   = 1 << 20
	flowUnconfirmedDown = 4 << 20
)

// pingQueueing is queueing for what the kernel cannot see: the backlog of a
// client's upload, or of a download towards a client this side dialed from.
// A PING's ACK waits behind whatever is queued between the peers, so the last
// round trip, or the wait for an ACK still due, above the lowest one this
// connection has seen is that backlog. Like the kernel's min_rtt, the floor
// is kept for the connection's life: a long transfer keeps the queue full, and
// a floor that forgot the empty path would rise with it. A PING samples it only
// once a second, so it reacts at half the queue the kernel signal tolerates.
func (c *flowConn) pingQueueing(now time.Time) int {
	if c.rttBase == 0 {
		return 0
	}
	last := c.rttLast
	if !c.pingSentAt.IsZero() {
		last = max(last, now.Sub(c.pingSentAt))
	}
	floor := c.pingFloor(now)
	switch q := last - floor; {
	case q > max(floor, flowQueueShrink):
		return 2
	case q > max(floor/2, flowQueueHold):
		return 1
	}
	return 0
}

// queueShrink trims a window that keeps a PING-seen queue standing: by a
// quarter once per PING sample, since a sample stays stale for a second, and
// never below what the reader takes over a round trip of the empty path, so
// the path stays full while the queue drains.
func (c *flowConn) queueShrink(w *flowWindow, now time.Time, init int32) {
	if w.qSample == c.rttSamples {
		return
	}
	w.qSample = c.rttSamples
	keep := w.prev * int64(c.pingFloor(now)) / int64(c.currentRTT())
	w.cap = int32(max(int64(init), int64(w.cap)/4*3, keep))
}

// NetConn returns the accepted connection, so that code which looks through
// connection wrappers, for the client's physical address or a PROXY header,
// still finds it behind the governor.
func (c *flowConn) NetConn() net.Conn {
	return c.Conn
}

func newFlowConn(c net.Conn, up, down flowLimit) *flowConn {
	fc := &flowConn{
		Conn:        c,
		up:          up,
		down:        down,
		streams:     make(map[uint32]*flowStream),
		wcredit:     make(map[uint32]int64),
		clientInit:  h2InitWindow,
		clientShown: h2InitWindow,
		serverInit:  h2InitWindow,
		serverShown: h2InitWindow,
	}
	fc.tcp = rawTCP(c)
	return fc
}

// newFlowClientConn governs the downlink of a connection this side dialed.
func newFlowClientConn(c net.Conn) *flowConn {
	fc := newFlowConn(c, flowLimit{}, flowDefault)
	fc.client = true
	return fc
}

func (c *flowConn) Read(b []byte) (int, error) {
	if len(c.rpending) > 0 {
		n := copy(b, c.rpending)
		c.rpending = c.rpending[n:]
		if len(c.rpending) == 0 {
			c.rpending = nil
		}
		return n, nil
	}
	for {
		if c.mode.Load() == flowPlain {
			return c.Conn.Read(b)
		}
		n, err := c.Conn.Read(b)
		if c.tlsConn != nil {
			c.followALPN()
			if c.mode.Load() == flowPlain {
				return n, err
			}
		}
		if ne, ok := err.(net.Error); err != nil && !(ok && ne.Timeout()) {
			c.release()
		}
		if n == 0 {
			return 0, err
		}
		in := bytespool.Alloc(int32(n))
		copy(in, b[:n])
		var out []byte
		if c.client {
			out = c.fromServer(in[:n], b[:0])
		} else {
			out = c.readFrames(in[:n], b[:0])
		}
		bytespool.Free(in)
		if c.isBroken() {
			c.Close()
			return 0, errFlowGivenUp
		}
		m := copy(b, out)
		if m < len(out) {
			c.rpending = append([]byte(nil), out[m:]...)
		}
		if m > 0 || err != nil {
			return m, err
		}
	}
}

func (c *flowConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// release drops all per-stream state once the connection is gone, so a
// connection object that lingers in some pool does not pin it.
func (c *flowConn) release() {
	c.mu.Lock()
	c.releaseLocked()
	c.mu.Unlock()
}

func (c *flowConn) releaseLocked() {
	c.streams = map[uint32]*flowStream{}
	c.opened = nil
	c.wqueue = nil
	clear(c.wcredit)
	c.closed = true
	if c.guard != nil {
		c.guard.Stop()
	}
}

// giveUp marks the connection for closing at the next read or write and
// drops its state at once: the peer lowered its window below the credit
// already handed on, or opened more streams than the governor tracks.
func (c *flowConn) giveUp() {
	c.broken = true
	c.releaseLocked()
}

func (c *flowConn) readFrames(in, out []byte) []byte {
	if c.mode.Load() == flowUndecided {
		for len(in) > 0 && c.prefix < len(h2Preface) {
			if in[0] != h2Preface[c.prefix] {
				c.mode.Store(flowPlain)
				return append(out, in...)
			}
			out = append(out, in[0])
			in = in[1:]
			c.prefix++
		}
		if c.prefix < len(h2Preface) {
			return out
		}
		c.mode.Store(flowH2)
	}
	c.mu.Lock()
	// A server pings only once the client preface is in: until then stock
	// sends nothing but its SETTINGS.
	c.pingReady = c.pingReady || (!c.client && c.settingsSent)
	out = c.rp.feed(in, out, (*flowReader)(c))
	credit := len(c.wcredit) > 0
	c.mu.Unlock()
	if credit {
		c.wakeQueue()
	}
	return out
}

func (c *flowConn) Write(b []byte) (int, error) {
	if c.client {
		return c.writeToServer(b)
	}
	if c.mode.Load() != flowH2 && !c.alpnH2.Load() {
		return c.Conn.Write(b)
	}
	c.wmu.Lock()
	out := bytespool.Alloc(int32(len(b) + 64))
	out = c.fromServer(b, out[:0])
	if c.isBroken() {
		bytespool.Free(out)
		c.wmu.Unlock()
		c.Close()
		return 0, errFlowGivenUp
	}
	err := c.send(out)
	bytespool.Free(out)
	c.wmu.Unlock()
	c.drainQueue()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// fromServer processes frames on their way from the server to the client.
func (c *flowConn) fromServer(in, out []byte) []byte {
	c.mu.Lock()
	out = c.wp.feed(in, out, (*flowWriter)(c))
	c.mu.Unlock()
	return out
}

func (c *flowConn) writeToServer(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.mode.Load() == flowPlain {
		return c.Conn.Write(b)
	}
	out := bytespool.Alloc(int32(len(b) + 64))
	out = c.readFrames(b, out[:0])
	if c.isBroken() {
		bytespool.Free(out)
		c.Close()
		return 0, errFlowGivenUp
	}
	err := c.send(out)
	bytespool.Free(out)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// injectToClient queues frames for the client without ever waiting for a
// write in progress: whoever holds wmu drains the queue after letting go.
// Only the guard's PING comes this way, and only one is ever queued.
func (c *flowConn) injectToClient(frames []byte) {
	c.mu.Lock()
	if c.closed || len(c.wqueue) > 0 {
		c.mu.Unlock()
		return
	}
	c.wqueue = append(c.wqueue, frames...)
	c.mu.Unlock()
	c.wakeQueue()
}

// creditClient queues upload credit for the client. Credit for one stream
// adds up in one entry, and the entry goes with the stream, so the queue
// never holds more than the streams the governor tracks.
func (c *flowConn) creditClient(id uint32, n int64) {
	c.wcredit[id] += n
}

// queuedLocked appends everything queued for the client.
func (c *flowConn) queuedLocked(out []byte) []byte {
	out = append(out, c.wqueue...)
	c.wqueue = nil
	for id, n := range c.wcredit {
		out = appendWindowUpdate(out, id, n)
	}
	clear(c.wcredit)
	return out
}

func (c *flowConn) wakeQueue() {
	c.wpending.Store(true)
	if c.wmu.TryLock() {
		go func() {
			c.flushQueueLocked()
			c.wmu.Unlock()
			c.drainQueue()
		}()
	}
}

func (c *flowConn) drainQueue() {
	for c.wpending.Load() && c.wmu.TryLock() {
		c.flushQueueLocked()
		c.wmu.Unlock()
	}
}

func (c *flowConn) flushQueueLocked() {
	c.wpending.Store(false)
	c.mu.Lock()
	var q []byte
	if c.settingsSent && c.wp.atBoundary() {
		q = c.queuedLocked(nil)
	}
	c.mu.Unlock()
	if len(q) > 0 {
		c.send(q)
	}
}

// send writes rewritten frames with wmu held. Once any part of them is lost,
// the peer's next frame would start inside a torn one, so a failed write ends
// the connection rather than letting later frames follow.
func (c *flowConn) send(b []byte) error {
	if _, err := c.Conn.Write(b); err != nil {
		c.Close()
		return err
	}
	return nil
}

func (c *flowConn) stream(id uint32) *flowStream {
	if id == 0 {
		return nil
	}
	return c.streams[id]
}

func (c *flowConn) finish(id uint32, s *flowStream) {
	if s.clientDone && s.serverDone {
		c.drop(id)
	}
}

func (c *flowConn) drop(id uint32) {
	delete(c.streams, id)
	delete(c.wcredit, id)
}

// upConnRelease is how much connection credit the client may be given: no
// more than the server granted, and no more than keeps the data sent and not
// yet read under what the streams whose readers return credit may hold, plus
// flowConnFloor for the rest. Streams nobody reads thus share Go's 1 MiB, as
// they would without the governor, whatever the server's own window, and
// slow readers holding their caps leave that room to new streams. A stream
// that holds more than its cap, because the cap shrank while its reader
// stalled, is allowed what it holds, so the excess does not come out of the
// room the others share. Shrinking a cap only stops further stream credit:
// what was granted before cannot be taken back and may still be spent, and
// the allowance follows it up to the window the server really grants.
func (c *flowConn) upConnRelease() int64 {
	var reading int64
	for _, s := range c.streams {
		// A finished upload needs no room, even while its response waits.
		if !s.clientDone && s.up.returned > 0 {
			reading += max(int64(s.up.cap), s.upSent-s.up.returned)
		}
	}
	// What the server has not read, from the connection's own counters: it
	// returns connection credit for every byte a handler reads, also on a
	// request the client has finished, where no stream credit comes back,
	// so a body read and held while its response waits is not counted.
	unread := max(c.upConnSent-(c.upConnReturned-c.upConnGrant), 0)
	bank := c.upConnReturned - c.upConnForwarded
	window := h2InitWindow + c.upConnForwarded - c.upConnSent
	return min(bank, flowConnFloor+reading-unread-window, h2MaxWindow)
}

func (c *flowConn) appendUpConnRelease(out []byte) []byte {
	rel := c.upConnRelease()
	if rel <= 0 || hold(rel, h2InitWindow+c.upConnForwarded-c.upConnSent, flowQuantumMax) {
		return out
	}
	c.upConnForwarded += rel
	return appendWindowUpdate(out, 0, rel)
}

// quantum is the least credit worth handing on for a window of cap: an
// eighth of it, between one and two default frames.
func quantum(cap int32) int64 {
	return min(max(int64(cap)/8, flowQuantumMin), flowQuantumMax)
}

// hold reports whether credit rel should wait for more. A reader returns
// credit a few KiB at a time; handed on like that, each piece makes the
// sender write one small frame, a system call and a TLS record each. While
// the sender still has a quantum of window it loses nothing by waiting, and
// what it sends then brings the next credit; once it has less, all credit
// goes out at once. No cap changes, so the reader holds no more than before.
func hold(rel, window, quantum int64) bool {
	return rel < quantum && window >= quantum
}

// currentRTT is the kernel's min_rtt where it vouches for the path, otherwise
// the lowest PING over the last one to two windows: PING queues behind data,
// so anything above the minimum is our own backlog and must not feed back into
// the caps.
func (c *flowConn) currentRTT() time.Duration {
	if c.rttBase != 0 && c.kOK && c.kstat.minRTT > 0 && 4*c.kstat.minRTT >= c.rttBase {
		return c.kstat.minRTT
	}
	switch {
	case c.rtt == 0:
		return flowDefaultRTT
	case c.rttPrev == 0:
		return c.rtt
	}
	return min(c.rtt, c.rttPrev)
}

func (c *flowConn) sampleRTT(now time.Time, sample time.Duration) {
	sample = max(sample, flowMinRTT)
	c.rttLast = sample
	c.rttSamples++
	if c.rttBase == 0 || sample < c.rttBase {
		c.rttBase = sample
	}
	if now.Sub(c.rttSince) >= flowRTTWindow {
		c.rttPrev, c.rtt, c.rttSince = c.rtt, 0, now
	}
	if c.rtt == 0 || sample < c.rtt {
		c.rtt = sample
	}
}

// appendPing adds a PING for the remote peer once a second while streams are
// open, so the connection knows its round trip. The first goes out as soon as
// both prefaces are through, before data can queue in front of its ACK, so the
// connection learns the round trip of the empty path. Once the kernel vouches
// for that round trip, no more are needed.
func (c *flowConn) appendPing(out []byte) []byte {
	if !c.pingReady {
		return out
	}
	// This runs at every frame boundary. Where the kernel vouches for the
	// path no PING is due, so the clock is read only now and then, to see
	// that it still does.
	if c.pingSkip > 0 {
		c.pingSkip--
		return out
	}
	now := time.Now()
	if c.modelled(now) {
		c.pingSkip = flowPingRecheck
		return out
	}
	if (len(c.streams) == 0 && c.rttBase != 0) || now.Sub(c.lastPing) < flowPingInterval ||
		(!c.pingSentAt.IsZero() && now.Sub(c.pingSentAt) < flowPingTimeout) {
		return out
	}
	c.pingSentAt, c.lastPing = now, now
	return c.appendPingFrame(out)
}

// flowPing is a PING of ours that has not been answered yet.
type flowPing struct {
	data uint64
	at   time.Time
}

// appendPingFrame adds a PING carrying fresh random data, as Go's own HTTP/2
// health checks do, and remembers it to recognize the ACK. The last
// flowPingSlots are remembered, so a guard probe sent while a periodic PING
// is due back does not make that one's ACK look foreign.
func (c *flowConn) appendPingFrame(out []byte) []byte {
	c.pingData = rand.Uint64()
	c.pings = append(c.pings, flowPing{c.pingData, time.Now()})
	if len(c.pings) > flowPingSlots {
		c.pings = c.pings[len(c.pings)-flowPingSlots:]
	}
	out = append(out, 0, 0, 8, h2Ping, 0, 0, 0, 0, 0)
	return binary.BigEndian.AppendUint64(out, c.pingData)
}

// pingAck reports whether a PING ACK answers one of ours, taking its round
// trip.
func (c *flowConn) pingAck(f h2Frame, payload []byte) bool {
	if f.flags&h2FlagAck == 0 {
		return false
	}
	data := binary.BigEndian.Uint64(payload)
	for i, p := range c.pings {
		if p.data != data {
			continue
		}
		c.pings = append(c.pings[:i], c.pings[i+1:]...)
		now := time.Now()
		c.sampleRTT(now, now.Sub(p.at))
		if !c.pingSentAt.After(p.at) {
			c.pingSentAt = time.Time{}
		}
		return true
	}
	return false
}

// flowGuardMin bounds how long a downlink stream may sit with the server out
// of window and no credit from the client before the guard steps in.
var flowGuardMin = 200 * time.Millisecond

func (c *flowConn) guardDelay() time.Duration {
	return max(4*c.currentRTT(), flowGuardMin)
}

// armGuard notes that s ran the server out of window while the client still
// owes it credit. Go clients hand credit back every few KiB they read; some
// HTTP/2 stacks only do so once half of their own, much larger, window is
// consumed and would never do it under a small cap. Until the client has
// shown it credits in small steps, a stream stuck like this gets probed.
func (c *flowConn) armGuard(s *flowStream) {
	if c.client || c.incremental || !s.down.waiting.IsZero() {
		return
	}
	if int64(c.clientShown)+s.downForwarded-s.downSent > 0 {
		return
	}
	if int64(c.clientInit)+s.down.returned-int64(c.clientShown)-s.downForwarded <= 0 {
		return
	}
	s.down.waiting = time.Now()
	if c.guard == nil {
		c.guard = time.AfterFunc(c.guardDelay(), c.fireGuard)
	} else {
		c.guard.Reset(c.guardDelay())
	}
}

// fireGuard asks the client for a PING: its ACK arrives on the read side,
// where stuck streams can then be given more room in order with other frames.
func (c *flowConn) fireGuard() {
	c.mu.Lock()
	if c.closed || c.incremental || !c.anyWaiting() {
		c.mu.Unlock()
		return
	}
	c.guardProbe = true
	c.pingSentAt = time.Now()
	ping := c.appendPingFrame(nil)
	c.mu.Unlock()
	c.injectToClient(ping)
}

// anyWaiting reports whether a stream still waits for credit: one that got
// it since the guard was armed needs no probe.
func (c *flowConn) anyWaiting() bool {
	for _, s := range c.streams {
		if !s.down.waiting.IsZero() {
			return true
		}
	}
	return false
}

// unstick grows the cap of every stream that has waited out the guard delay
// to at least half the client's own window, then doubles it on each further
// probe, and hands the server what that allows.
func (c *flowConn) unstick(now time.Time, out []byte) []byte {
	c.guardProbe = false
	delay := c.guardDelay()
	again := false
	for id, s := range c.streams {
		if s.down.waiting.IsZero() {
			continue
		}
		if now.Sub(s.down.waiting) < delay {
			again = true
			continue
		}
		s.down.cap = int32(min(int64(c.down.max), max(2*int64(s.down.cap), int64(c.clientInit)/2+flowSmallCredit)))
		s.down.waiting = time.Time{}
		if rel := c.downRelease(s); rel > 0 {
			s.downForwarded += rel
			out = appendWindowUpdate(out, id, rel)
		}
	}
	if again && c.guard != nil {
		c.guard.Reset(delay)
	}
	return out
}

// upRelease is how much credit the client may be given on s: no more than the
// server granted, and no more than keeps the handler's unread data under cap.
func (c *flowConn) upRelease(s *flowStream) int64 {
	bank := int64(c.serverInit) + s.up.returned - int64(max(h2InitWindow, c.serverShown)) - s.upForwarded
	unread := s.upSent - s.up.returned
	window := int64(c.serverShown) + s.upForwarded - s.upSent
	return min(bank, int64(s.up.cap)-unread-window, h2MaxWindow)
}

// downRelease is how much credit the server may be given on s: no more than
// the client granted, and no more than keeps the client's unread data under cap.
//
// On a server the streams of one connection also share sendWindow. A cap
// follows its own reader, but many streams starting at once on a fast link
// each look fast for a moment, and the client has to hold their sum: twenty
// of them took a client past 40 MiB within a second. What the client holds is
// counted as the server may still send it: unread data and unused window. A
// client that itself grants one stream more than sendWindow has that room, so
// its own window is the limit then; that is how a bridge with raised windows
// differs from a phone on the same inbound. A stream always has the
// protocol's default window, which SETTINGS already gave it, so none waits
// for the others; streams opened once the limit is used up add that much each.
func (c *flowConn) downRelease(s *flowStream) int64 {
	bank := int64(c.clientInit) + s.down.returned - int64(c.clientShown) - s.downForwarded
	held := int64(c.clientShown) + s.downForwarded - s.down.returned
	rel := min(bank, int64(s.down.cap)-held, h2MaxWindow)
	if rel <= 0 || c.client || c.sendWindow == 0 {
		return rel
	}
	total := int64(0)
	for _, o := range c.streams {
		if !o.serverDone {
			total += int64(c.clientShown) + o.downForwarded - o.down.returned
		}
	}
	limit := max(c.sendWindow, int64(c.clientInit))
	return min(rel, max(limit-total, h2InitWindow-held))
}

func appendWindowUpdate(out []byte, stream uint32, n int64) []byte {
	out = append(out, 0, 0, 4, h2WindowUpdate, 0)
	out = binary.BigEndian.AppendUint32(out, stream)
	return binary.BigEndian.AppendUint32(out, uint32(n))
}

func rewriteInitialWindow(payload []byte, limit int32) (real, shown int32, found bool) {
	for i := 0; i+6 <= len(payload); i += 6 {
		if binary.BigEndian.Uint16(payload[i:]) != h2SettingInitialWindowSize {
			continue
		}
		real = int32(min(binary.BigEndian.Uint32(payload[i+2:]), h2MaxWindow))
		shown = min(real, limit)
		binary.BigEndian.PutUint32(payload[i+2:], uint32(shown))
		found = true
	}
	return
}

// changeInitialWindow applies a SETTINGS_INITIAL_WINDOW_SIZE in payload to
// one direction. The sender moves every open stream by the change of the
// value it is shown, the receiver by the change of the real one, so credit
// already forwarded beyond the shown window has to come off the shown value:
// for each stream shown + forwarded <= real + returned. Where no value is
// low enough, ok is false and the connection has to go. Streams the sender
// has finished do not count: nothing more is sent on them.
func (c *flowConn) changeInitialWindow(payload []byte, l flowLimit, start int32, init, shown *int32, credit func(*flowStream) (returned, forwarded int64, done bool)) (ok bool) {
	real, show, found := rewriteInitialWindow(payload, max(l.init, start))
	if !found {
		return true
	}
	for _, s := range c.streams {
		returned, forwarded, done := credit(s)
		if done {
			continue
		}
		lim := int64(real) + returned - forwarded
		if lim < 0 {
			return false
		}
		show = int32(min(int64(show), lim))
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		if binary.BigEndian.Uint16(payload[i:]) == h2SettingInitialWindowSize {
			binary.BigEndian.PutUint32(payload[i+2:], uint32(show))
		}
	}
	*init, *shown = real, show
	return true
}

// errFlowGivenUp ends a connection the governor gave up, see giveUp.
var errFlowGivenUp = errors.New("http2 flow governor: connection given up")

// isBroken reports whether the connection has to go, see giveUp.
func (c *flowConn) isBroken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.broken
}

// capFrameSize lowers the largest frame the peer is told it may send to the
// HTTP/2 default. The local stack still takes frames up to what it really
// allows, but its frame reader keeps a buffer as large as the largest frame
// it has ever read, for as long as the connection lives.
func capFrameSize(payload []byte) {
	for i := 0; i+6 <= len(payload); i += 6 {
		if binary.BigEndian.Uint16(payload[i:]) == h2SettingMaxFrameSize {
			binary.BigEndian.PutUint32(payload[i+2:], min(binary.BigEndian.Uint32(payload[i+2:]), h2MinMaxFrameSize))
		}
	}
}

// flowReader handles frames from the client to the server.
type flowReader flowConn

func (r *flowReader) frame(f h2Frame) {
	c := (*flowConn)(r)
	switch f.typ {
	case h2Headers:
		s := c.stream(f.stream)
		if s == nil && f.stream%2 == 1 && !c.closed {
			if len(c.streams) >= flowMaxStreams {
				c.giveUp()
				return
			}
			now := time.Now()
			s = &flowStream{}
			s.up.cap = max(c.upLearned.value(now, c.up.init), flowStartWindow)
			s.down.cap = max(c.downLearned.value(now, c.down.init), flowStartWindow)
			c.streams[f.stream] = s
			c.opened = append(c.opened, f.stream)
		}
		if s != nil && f.flags&h2FlagEndStream != 0 {
			s.clientDone = true
			c.finish(f.stream, s)
		}
	case h2Data:
		c.upConnSent += int64(f.length)
		if s := c.stream(f.stream); s != nil {
			s.upSent += int64(f.length)
			if f.flags&h2FlagEndStream != 0 {
				s.clientDone = true
				c.finish(f.stream, s)
			}
		}
	case h2RSTStream:
		c.drop(f.stream)
	}
}

func (r *flowReader) control(f h2Frame, header, payload, out []byte) []byte {
	c := (*flowConn)(r)
	switch f.typ {
	case h2Settings:
		if f.flags&h2FlagAck == 0 && validSettings(payload) {
			if c.down.enabled() && !c.changeInitialWindow(payload, c.down, flowShownDown, &c.clientInit, &c.clientShown, func(s *flowStream) (int64, int64, bool) {
				return s.down.returned, s.downForwarded, s.serverDone
			}) {
				c.giveUp()
				return out
			}
			capFrameSize(payload)
			c.pingReady = c.pingReady || c.client
			out = append(out, header...)
			out = append(out, payload...)
			// A raised window funds credit the receiver no longer owes.
			if c.down.enabled() {
				for id, s := range c.streams {
					if s.serverDone {
						continue
					}
					if rel := c.downRelease(s); rel > 0 {
						s.downForwarded += rel
						out = appendWindowUpdate(out, id, rel)
					}
				}
			}
			return out
		}
	case h2Ping:
		if !c.client && c.pingAck(f, payload) {
			if c.guardProbe {
				return c.unstick(time.Now(), out)
			}
			return out
		}
	case h2WindowUpdate:
		inc := int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
		s := c.stream(f.stream)
		if s == nil || inc == 0 || !c.down.enabled() {
			break
		}
		now := time.Now()
		s.down.returned += inc
		s.down.waiting = time.Time{}
		if inc < flowSmallCredit {
			c.incremental = true
		}
		var q int
		switch {
		case c.client && c.modelled(now):
		case c.client:
			q = c.pingQueueing(now)
		default:
			q = c.queueing(now)
		}
		switch {
		case c.client && c.modelled(now) && s.down.ramped:
			s.down.model(now, c.currentRTT(), c.down.init, c.down.max)
		case !c.client && c.incremental && s.down.flat >= flowFullRounds && c.modelled(now):
			// Only clients that credit in small steps: one that waits for
			// half of its own window could be held below that half. Only
			// where the kernel sees the path: behind a TCP proxy it sees
			// no queue at all.
			s.down.pi(now, c.kstat, c.down.init, c.down.max)
		default:
			s.down.adjust(now, c.currentRTT(), c.down.init, c.down.max, c.client || c.incremental, q > 0)
		}
		switch {
		case c.client:
			if q == 2 {
				c.queueShrink(&s.down, now, c.down.init)
			}
			if !c.floorConfirmed(now) {
				s.down.cap = min(s.down.cap, flowUnconfirmedDown)
			}
		case q == 2 && now.Sub(s.down.qAt) >= c.currentRTT():
			s.down.qAt = now
			s.down.cap = max(c.down.init, s.down.cap/4*3)
		}
		c.downLearned.note(now, c.down.init, s.down.cap)
		rel := c.downRelease(s)
		if rel <= 0 || hold(rel, int64(c.clientShown)+s.downForwarded-s.downSent, quantum(s.down.cap)) {
			return out
		}
		s.downForwarded += rel
		return appendWindowUpdate(out, f.stream, rel)
	}
	out = append(out, header...)
	return append(out, payload...)
}

func (r *flowReader) boundary(out []byte) []byte {
	c := (*flowConn)(r)
	for _, id := range c.opened {
		s := c.stream(id)
		if s == nil {
			continue
		}
		if c.down.enabled() {
			if rel := c.downRelease(s); rel > 0 {
				s.downForwarded += rel
				out = appendWindowUpdate(out, id, rel)
			}
		}
		// Like the stock server, grant no upload credit to a request that
		// has already ended.
		if c.up.enabled() && !s.clientDone {
			if rel := c.upRelease(s); rel > 0 {
				s.upForwarded += rel
				c.creditClient(id, rel)
			}
		}
	}
	c.opened = c.opened[:0]
	if c.client {
		out = c.appendPing(out)
	}
	return out
}

// flowWriter handles frames from the server to the client.
type flowWriter flowConn

func (w *flowWriter) frame(f h2Frame) {
	c := (*flowConn)(w)
	s := c.stream(f.stream)
	switch f.typ {
	case h2Data:
		if s != nil {
			s.downSent += int64(f.length)
			if c.down.enabled() {
				c.armGuard(s)
			}
		}
		fallthrough
	case h2Headers:
		if s != nil && f.flags&h2FlagEndStream != 0 {
			s.serverDone = true
			c.finish(f.stream, s)
		}
	case h2RSTStream:
		c.drop(f.stream)
	}
}

func (w *flowWriter) control(f h2Frame, header, payload, out []byte) []byte {
	c := (*flowConn)(w)
	switch f.typ {
	case h2Settings:
		if f.flags&h2FlagAck == 0 && validSettings(payload) {
			if c.up.enabled() && !c.changeInitialWindow(payload, c.up, flowShownUp, &c.serverInit, &c.serverShown, func(s *flowStream) (int64, int64, bool) {
				return s.up.returned, s.upForwarded, s.clientDone
			}) {
				c.giveUp()
				return out
			}
			capFrameSize(payload)
			c.settingsSent = true
			c.pingReady = c.pingReady || (!c.client && c.mode.Load() == flowH2)
			out = append(out, header...)
			out = append(out, payload...)
			if c.up.enabled() {
				for id, s := range c.streams {
					if s.clientDone {
						continue
					}
					if rel := c.upRelease(s); rel > 0 {
						s.upForwarded += rel
						out = appendWindowUpdate(out, id, rel)
					}
				}
			}
			return out
		}
	case h2Ping:
		if c.client && c.pingAck(f, payload) {
			return out
		}
	case h2WindowUpdate:
		inc := int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
		if f.stream == 0 && inc > 0 && c.up.enabled() {
			c.upConnReturned += inc
			if !c.upConnGrantKnown && c.upConnSent == 0 {
				c.upConnGrant += inc
			}
			return c.appendUpConnRelease(out)
		}
		s := c.stream(f.stream)
		if s == nil || inc == 0 || !c.up.enabled() {
			break
		}
		now := time.Now()
		s.up.returned += inc
		var q int
		switch {
		case c.modelled(now) && s.up.ramped:
			s.up.model(now, c.currentRTT(), c.up.init, c.up.max)
		case c.modelled(now):
			s.up.adjust(now, c.currentRTT(), c.up.init, c.up.max, true, false)
		default:
			q = c.pingQueueing(now)
			s.up.adjust(now, c.currentRTT(), c.up.init, c.up.max, true, q > 0)
		}
		if q == 2 {
			c.queueShrink(&s.up, now, c.up.init)
		}
		if !c.floorConfirmed(now) {
			s.up.cap = min(s.up.cap, flowUnconfirmedUp)
		}
		c.upLearned.note(now, c.up.init, s.up.cap)
		if rel := c.upRelease(s); rel > 0 && !hold(rel, int64(c.serverShown)+s.upForwarded-s.upSent, quantum(s.up.cap)) {
			s.upForwarded += rel
			out = appendWindowUpdate(out, f.stream, rel)
		}
		// What the reader took also frees room on the connection.
		return c.appendUpConnRelease(out)
	}
	out = append(out, header...)
	return append(out, payload...)
}

func (w *flowWriter) boundary(out []byte) []byte {
	c := (*flowConn)(w)
	if c.client || !c.settingsSent {
		return out
	}
	out = c.queuedLocked(out)
	return c.appendPing(out)
}

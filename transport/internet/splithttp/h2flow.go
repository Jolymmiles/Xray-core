package splithttp

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/platform"
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
	h2Ping         = 0x6
	h2WindowUpdate = 0x8
	h2Continuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4

	h2SettingInitialWindowSize = 0x4
	h2SettingMaxFrameSize      = 0x5
	h2MinMaxFrameSize          = 16384

	flowPingInterval = time.Second
	flowPingTimeout  = 10 * time.Second
	flowDefaultRTT   = 200 * time.Millisecond
	flowRTTWindow    = 10 * time.Second
	flowMinRTT       = time.Millisecond
	flowLearnHalf    = time.Minute
	flowStartWindow  = 256 << 10
	flowSmallCredit  = 64 << 10
	flowShrinkAfter  = 3
	flowKernelEvery  = 20 * time.Millisecond
	flowQueueHold    = 15 * time.Millisecond
	flowQueueShrink  = 40 * time.Millisecond

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

type tcpStats struct {
	rtt, minRTT time.Duration
}

type flowListener struct {
	net.Listener
	up, down flowLimit
}

func (l *flowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newFlowConn(c, l.up, l.down), nil
}

type h2Frame struct {
	typ, flags byte
	stream     uint32
	length     int
}

func (f h2Frame) control() bool {
	switch f.typ {
	case h2Settings:
		return f.length%6 == 0 && f.length <= 16384
	case h2Ping:
		return f.length == 8
	case h2WindowUpdate:
		return f.length == 4
	}
	return false
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
			if p.f.control() {
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
	case h2Headers, h2Continuation:
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
	pingData    uint64
	pingSentAt  time.Time
	lastPing    time.Time

	incremental bool
	guard       *time.Timer
	guardProbe  bool

	rp       frameParser
	rpending []byte
	prefix   int
	opened   []uint32
	toClient []byte

	wmu          sync.Mutex
	wp           frameParser
	wqueue       []byte
	wpending     atomic.Bool
	settingsSent bool
	pingReady    bool
	closed       bool

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
	if c.tcp == nil {
		return 0
	}
	if now.Sub(c.kAt) >= flowKernelEvery {
		c.kAt = now
		c.kstat, c.kOK = readTCPStats(c.tcp)
	}
	if !c.kOK || c.kstat.minRTT <= 0 {
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

func newFlowConn(c net.Conn, up, down flowLimit) *flowConn {
	fc := &flowConn{
		Conn:        c,
		up:          up,
		down:        down,
		streams:     make(map[uint32]*flowStream),
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
	c.streams = map[uint32]*flowStream{}
	c.opened = nil
	c.toClient = nil
	c.wqueue = nil
	c.closed = true
	if c.guard != nil {
		c.guard.Stop()
	}
	c.mu.Unlock()
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
	out = c.rp.feed(in, out, (*flowReader)(c))
	toClient := c.toClient
	c.toClient = nil
	c.mu.Unlock()
	if len(toClient) > 0 {
		c.injectToClient(toClient)
	}
	return out
}

func (c *flowConn) Write(b []byte) (int, error) {
	if c.client {
		return c.writeToServer(b)
	}
	if c.mode.Load() != flowH2 {
		return c.Conn.Write(b)
	}
	c.wmu.Lock()
	out := bytespool.Alloc(int32(len(b) + 64))
	out = c.fromServer(b, out[:0])
	_, err := c.Conn.Write(out)
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
	_, err := c.Conn.Write(out)
	bytespool.Free(out)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// injectToClient queues frames for the client without ever waiting for a
// write in progress: whoever holds wmu drains the queue after letting go.
func (c *flowConn) injectToClient(frames []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.wqueue = append(c.wqueue, frames...)
	c.mu.Unlock()
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
		q, c.wqueue = c.wqueue, nil
	}
	c.mu.Unlock()
	if len(q) > 0 {
		c.Conn.Write(q)
	}
}

func (c *flowConn) stream(id uint32) *flowStream {
	if id == 0 {
		return nil
	}
	return c.streams[id]
}

func (c *flowConn) finish(id uint32, s *flowStream) {
	if s.clientDone && s.serverDone {
		delete(c.streams, id)
	}
}

// currentRTT is the lowest round trip seen over the last one to two windows:
// PING queues behind data, so anything above the minimum is our own backlog
// and must not feed back into the caps.
func (c *flowConn) currentRTT() time.Duration {
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
	if now.Sub(c.rttSince) >= flowRTTWindow {
		c.rttPrev, c.rtt, c.rttSince = c.rtt, 0, now
	}
	if c.rtt == 0 || sample < c.rtt {
		c.rtt = sample
	}
}

// appendPing adds a PING for the remote peer once a second while streams are
// open, so the connection knows its round trip.
func (c *flowConn) appendPing(out []byte) []byte {
	now := time.Now()
	if !c.pingReady || len(c.streams) == 0 || now.Sub(c.lastPing) < flowPingInterval ||
		(!c.pingSentAt.IsZero() && now.Sub(c.pingSentAt) < flowPingTimeout) {
		return out
	}
	c.pingSentAt, c.lastPing = now, now
	return c.appendPingFrame(out)
}

// appendPingFrame adds a PING carrying fresh random data, as Go's own HTTP/2
// health checks do, and remembers it to recognize the ACK.
func (c *flowConn) appendPingFrame(out []byte) []byte {
	c.pingData = rand.Uint64()
	out = append(out, 0, 0, 8, h2Ping, 0, 0, 0, 0, 0)
	return binary.BigEndian.AppendUint64(out, c.pingData)
}

// pingAck reports whether a PING ACK answers ours, taking its round trip.
func (c *flowConn) pingAck(f h2Frame, payload []byte) bool {
	if f.flags&h2FlagAck == 0 || binary.BigEndian.Uint64(payload) != c.pingData || c.pingSentAt.IsZero() {
		return false
	}
	now := time.Now()
	c.sampleRTT(now, now.Sub(c.pingSentAt))
	c.pingSentAt = time.Time{}
	return true
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
	if c.closed || c.incremental {
		c.mu.Unlock()
		return
	}
	c.guardProbe = true
	c.pingSentAt = time.Now()
	ping := c.appendPingFrame(nil)
	c.mu.Unlock()
	c.injectToClient(ping)
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
func (c *flowConn) downRelease(s *flowStream) int64 {
	bank := int64(c.clientInit) + s.down.returned - int64(c.clientShown) - s.downForwarded
	unread := s.downSent - s.down.returned
	window := int64(c.clientShown) + s.downForwarded - s.downSent
	return min(bank, int64(s.down.cap)-unread-window, h2MaxWindow)
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
		if s := c.stream(f.stream); s != nil {
			s.upSent += int64(f.length)
			if f.flags&h2FlagEndStream != 0 {
				s.clientDone = true
				c.finish(f.stream, s)
			}
		}
	case h2RSTStream:
		delete(c.streams, f.stream)
	}
}

func (r *flowReader) control(f h2Frame, header, payload, out []byte) []byte {
	c := (*flowConn)(r)
	switch f.typ {
	case h2Settings:
		if f.flags&h2FlagAck == 0 {
			if c.down.enabled() {
				if real, shown, ok := rewriteInitialWindow(payload, c.down.init); ok {
					c.clientInit, c.clientShown = real, shown
				}
			}
			capFrameSize(payload)
			c.pingReady = c.pingReady || c.client
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
		q := 0
		if !c.client {
			q = c.queueing(now)
		}
		s.down.adjust(now, c.currentRTT(), c.down.init, c.down.max, c.client || c.incremental, q > 0)
		if q == 2 && now.Sub(s.down.qAt) >= c.currentRTT() {
			s.down.qAt = now
			s.down.cap = max(c.down.init, s.down.cap/4*3)
		}
		c.downLearned.note(now, c.down.init, s.down.cap)
		rel := c.downRelease(s)
		if rel <= 0 {
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
		if c.up.enabled() {
			if rel := c.upRelease(s); rel > 0 {
				s.upForwarded += rel
				c.toClient = appendWindowUpdate(c.toClient, id, rel)
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
		delete(c.streams, f.stream)
	}
}

func (w *flowWriter) control(f h2Frame, header, payload, out []byte) []byte {
	c := (*flowConn)(w)
	switch f.typ {
	case h2Settings:
		if f.flags&h2FlagAck == 0 {
			if c.up.enabled() {
				if real, shown, ok := rewriteInitialWindow(payload, c.up.init); ok {
					c.serverInit, c.serverShown = real, shown
				}
			}
			capFrameSize(payload)
			c.settingsSent = true
			c.pingReady = c.pingReady || !c.client
		}
	case h2Ping:
		if c.client && c.pingAck(f, payload) {
			return out
		}
	case h2WindowUpdate:
		inc := int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
		s := c.stream(f.stream)
		if s == nil || inc == 0 || !c.up.enabled() {
			break
		}
		now := time.Now()
		s.up.returned += inc
		s.up.adjust(now, c.currentRTT(), c.up.init, c.up.max, true, false)
		c.upLearned.note(now, c.up.init, s.up.cap)
		rel := c.upRelease(s)
		if rel <= 0 {
			return out
		}
		s.upForwarded += rel
		return appendWindowUpdate(out, f.stream, rel)
	}
	out = append(out, header...)
	return append(out, payload...)
}

func (w *flowWriter) boundary(out []byte) []byte {
	c := (*flowConn)(w)
	if c.client || !c.settingsSent {
		return out
	}
	if len(c.wqueue) > 0 {
		out = append(out, c.wqueue...)
		c.wqueue = nil
	}
	return c.appendPing(out)
}

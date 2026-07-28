// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acceptBacklog = 512
	writeBacklog  = 256
)

// carrierWatchDelay is how long a stream may hold readLoop before readLoop hands
// the carrier to a watcher. readLoop is the session's only reader, so while it
// waits for stream buffer space nobody can observe a peer FIN: what ends the
// wait early is a closed s.done, and what closes s.done on carrier death is
// readLoop itself. Until the wait expires -- StreamStallTimeout, 30s by default,
// per stalled frame -- the session, both loops, the carrier conn and every
// queued buffer stay pinned.
//
// The delay keeps the healthy path free: a stream that frees space promptly
// never costs a watcher goroutine.
//
// A var rather than a const so a test can disable the watcher by configuration
// and measure the wait it removes, instead of neutering production code to do it.
// Nothing writes it in production. A test that does must restore it, and that is
// only safe while no test in this package calls t.Parallel() -- check that before
// adding one, or the control subtest starts racing whatever runs alongside it.
var carrierWatchDelay = 200 * time.Millisecond

// carrierWatch is one outstanding read-ahead of the next frame header.
type carrierWatch struct {
	read int
	err  error
}

type outboundFrame struct {
	encoded []byte
	result  chan error
}

type Session struct {
	conn   io.ReadWriteCloser
	config Config
	client bool

	nextStreamID atomic.Uint32
	streamsMu    sync.Mutex
	streams      map[uint32]*Stream
	accepts      chan *Stream

	writeQueue chan outboundFrame
	submitMu   sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
	loops      sync.WaitGroup
	errorMu    sync.Mutex
	lastError  error

	receiveMu      sync.Mutex
	receiveUsed    int
	receiveChanged chan struct{}

	acceptMu       sync.Mutex
	acceptDeadline time.Time
	acceptChanged  chan struct{}

	lastReceive atomic.Int64
	// readHeader, readHeaderLen and watch belong to readLoop alone. It is the
	// session's only carrier reader; a watcher borrows that role for one read at
	// a time and readLoop joins it before touching the carrier again.
	readHeader    [frameHeaderSize]byte
	readHeaderLen int
	watch         chan carrierWatch
}

func newSession(conn io.ReadWriteCloser, config *Config, client bool) (*Session, error) {
	if conn == nil {
		return nil, errors.New("SMUX connection is required")
	}
	if config == nil {
		config = DefaultConfig()
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	session := &Session{
		conn:           conn,
		config:         *config,
		client:         client,
		streams:        make(map[uint32]*Stream),
		accepts:        make(chan *Stream, acceptBacklog),
		writeQueue:     make(chan outboundFrame, writeBacklog),
		done:           make(chan struct{}),
		receiveChanged: make(chan struct{}, 1),
		acceptChanged:  make(chan struct{}),
	}
	if client {
		session.nextStreamID.Store(1)
	}
	if !session.config.KeepAliveDisabled {
		session.lastReceive.Store(time.Now().UnixNano())
	}
	loopCount := 2
	if !session.config.KeepAliveDisabled {
		loopCount++
	}
	session.loops.Add(loopCount)
	go func() {
		defer session.loops.Done()
		session.writeLoop()
	}()
	go func() {
		defer session.loops.Done()
		session.readLoop()
	}()
	if !session.config.KeepAliveDisabled {
		go func() {
			defer session.loops.Done()
			session.keepaliveLoop()
		}()
	}
	return session, nil
}

func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, s.terminalError()
	}
	streamID := s.nextStreamID.Add(2)
	if streamID < 2 {
		return nil, errors.New("SMUX stream ID space exhausted")
	}
	stream := newStream(s, streamID)
	s.streamsMu.Lock()
	s.streams[streamID] = stream
	s.streamsMu.Unlock()
	if err := s.submitResult(frameOpen, streamID, nil, time.Time{}, stream.writeResult); err != nil {
		s.removeStream(streamID)
		stream.sessionStopped()
		return nil, err
	}
	return stream, nil
}

func (s *Session) Open() (io.ReadWriteCloser, error) {
	return s.OpenStream()
}

func (s *Session) AcceptStream() (*Stream, error) {
	for {
		if s.IsClosed() {
			return nil, s.terminalError()
		}
		deadline, changed := s.acceptState()
		deadlineChannel, stopTimer := deadlineSignal(deadline)
		select {
		case stream := <-s.accepts:
			stopTimer()
			if s.IsClosed() {
				return nil, s.terminalError()
			}
			return stream, nil
		case <-changed:
			stopTimer()
			continue
		case <-deadlineChannel:
			stopTimer()
			return nil, ErrTimeout
		case <-s.done:
			stopTimer()
			return nil, s.terminalError()
		}
	}
}

func (s *Session) Accept() (io.ReadWriteCloser, error) {
	return s.AcceptStream()
}

func (s *Session) Close() error {
	s.fail(io.ErrClosedPipe)
	s.loops.Wait()
	return nil
}

func (s *Session) CloseChan() <-chan struct{} {
	return s.done
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Session) NumStreams() int {
	if s.IsClosed() {
		return 0
	}
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	return len(s.streams)
}

func (s *Session) SetDeadline(deadline time.Time) error {
	s.acceptMu.Lock()
	s.acceptDeadline = deadline
	close(s.acceptChanged)
	s.acceptChanged = make(chan struct{})
	s.acceptMu.Unlock()
	return nil
}

func (s *Session) LocalAddr() net.Addr {
	if connection, ok := s.conn.(interface{ LocalAddr() net.Addr }); ok {
		return connection.LocalAddr()
	}
	return nil
}

func (s *Session) RemoteAddr() net.Addr {
	if connection, ok := s.conn.(interface{ RemoteAddr() net.Addr }); ok {
		return connection.RemoteAddr()
	}
	return nil
}

func (s *Session) writeLoop() {
	for {
		select {
		case request := <-s.writeQueue:
			err := s.writeFrame(request.encoded)
			releaseFrameBuffer(request.encoded)
			request.result <- err
			if err != nil {
				s.fail(err)
				s.failQueuedWrites(err)
				return
			}
		case <-s.done:
			s.failQueuedWrites(s.terminalError())
			return
		}
	}
}

func (s *Session) writeFrame(encoded []byte) error {
	for len(encoded) > 0 {
		written, err := s.conn.Write(encoded)
		if written > 0 {
			encoded = encoded[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *Session) submitResult(command frameCommand, streamID uint32, payload []byte, deadline time.Time, result chan error) error {
	return s.submitWithStateResult(command, streamID, payload, func() (time.Time, <-chan struct{}, error) {
		return deadline, nil, nil
	}, result)
}

func (s *Session) trySubmitControl(command frameCommand, streamID uint32) bool {
	encoded := acquireFrameBuffer(frameHeaderSize)
	encodeFrameHeader((*[frameHeaderSize]byte)(encoded), command, streamID, 0)
	request := outboundFrame{encoded: encoded, result: make(chan error, 1)}

	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if s.IsClosed() {
		releaseFrameBuffer(encoded)
		return false
	}
	select {
	case s.writeQueue <- request:
		return true
	default:
		releaseFrameBuffer(encoded)
		return false
	}
}

func (s *Session) submitWithStateResult(command frameCommand, streamID uint32, payload []byte, state func() (time.Time, <-chan struct{}, error), result chan error) error {
	// A timed-out or failed submit may return while the writer is still finishing
	// the queued frame. Give the writer private storage so callers may immediately
	// reuse their buffer without racing the carrier write.
	encoded := acquireFrameBuffer(frameHeaderSize + len(payload))
	encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
	copy(encoded[frameHeaderSize:], payload)
	request := outboundFrame{encoded: encoded, result: result}
	for {
		deadline, changed, err := state()
		if err != nil {
			releaseFrameBuffer(encoded)
			return err
		}
		deadlineChannel, stopTimer := deadlineSignal(deadline)
		s.submitMu.Lock()
		if s.IsClosed() {
			s.submitMu.Unlock()
			stopTimer()
			releaseFrameBuffer(encoded)
			return s.terminalError()
		}
		select {
		case s.writeQueue <- request:
			s.submitMu.Unlock()
			stopTimer()
			goto queued
		case <-deadlineChannel:
			s.submitMu.Unlock()
			stopTimer()
			releaseFrameBuffer(encoded)
			return ErrTimeout
		case <-changed:
			s.submitMu.Unlock()
			stopTimer()
		case <-s.done:
			// Without this case the send is the only live one for a caller that
			// passes neither a deadline nor a change channel (submitResult, and
			// OpenStream's zero deadline). A full writeQueue would then park
			// here holding submitMu until the process exits (D8).
			s.submitMu.Unlock()
			stopTimer()
			releaseFrameBuffer(encoded)
			return s.terminalError()
		}
	}

queued:
	for {
		// Once a frame is queued, its carrier write decides whether those bytes
		// were accepted. Prefer a concurrently completed write over the terminal
		// session error, while still letting Close unblock a stuck carrier.
		deadline, changed, _ := state()
		deadlineChannel, stopTimer := deadlineSignal(deadline)
		select {
		case err := <-request.result:
			stopTimer()
			return err
		case <-deadlineChannel:
			stopTimer()
			return ErrTimeout
		case <-changed:
			stopTimer()
		case <-s.done:
			stopTimer()
			select {
			case err := <-request.result:
				return err
			default:
				return s.terminalError()
			}
		}
	}
}

func (s *Session) failQueuedWrites(err error) {
	for {
		select {
		case request := <-s.writeQueue:
			releaseFrameBuffer(request.encoded)
			request.result <- err
		default:
			return
		}
	}
}

func (s *Session) readLoop() {
	// A watch borrows the carrier; readLoop must not hand the session back to
	// Close while a goroutine still holds it. Every exit path here has already
	// failed the session, which closes the carrier, so this join cannot hang.
	defer s.joinCarrierWatch()
	for {
		if err := s.readFrameHeader(); err != nil {
			s.fail(err)
			return
		}
		if !s.config.KeepAliveDisabled {
			s.lastReceive.Store(time.Now().UnixNano())
		}
		header, err := decodeFrameHeader(&s.readHeader)
		if err != nil || !s.validInboundFrame(header) {
			s.fail(ErrInvalidProtocol)
			return
		}
		switch header.command {
		case frameOpen:
			s.acceptRemoteStream(header.streamID)
		case frameClose:
			if stream := s.lookupStream(header.streamID); stream != nil {
				stream.remoteStopped()
			}
		case frameData:
			if header.length == 0 {
				continue
			}
			length := int(header.length)
			if !s.reserveReceive(length) {
				return
			}
			payload := acquireReceiveBuffer(length)
			if err := payload.readFullFrom(s.conn, length); err != nil {
				releaseReceiveBuffer(payload)
				s.releaseReceive(length)
				s.fail(err)
				return
			}
			stream := s.lookupStream(header.streamID)
			if stream == nil {
				releaseReceiveBuffer(payload)
				s.releaseReceive(length)
				continue
			}
			enqueueResult := s.enqueueWatchingCarrier(stream, payload)
			if enqueueResult == streamEnqueueQueued {
				continue
			}
			releaseReceiveBuffer(payload)
			s.releaseReceive(length)
			if enqueueResult == streamEnqueueStalled {
				if err := stream.Abort(); err != nil {
					return
				}
			}
		case frameKeepalive:
		}
	}
}

// readFrameHeader fills readHeader, resuming from whatever a carrier watcher
// already collected.
func (s *Session) readFrameHeader() error {
	if result, joined := s.joinCarrierWatch(); joined && result.err != nil {
		return result.err
	}
	if s.readHeaderLen < len(s.readHeader) {
		read, err := io.ReadFull(s.conn, s.readHeader[s.readHeaderLen:])
		s.readHeaderLen += read
		if err != nil {
			return err
		}
	}
	s.readHeaderLen = 0
	return nil
}

// startCarrierWatch moves readLoop's next header read onto its own goroutine, so
// that a carrier dying while readLoop waits for buffer space is still noticed.
// Only a read can observe a peer FIN, and a blocking read is the only form of it
// that works everywhere: every server-side carrier arrives as a *cnc.Connection,
// whose SetReadDeadline is a no-op that returns nil, so a deadline-bounded probe
// would silently become an unbounded read and wedge readLoop for good.
//
// At most one watch is outstanding: readLoop starts one here and joins it in
// readFrameHeader before touching the carrier again, so the two never read
// concurrently and readHeader has a single writer at a time.
//
// ponytail: the read-ahead ceiling is one header. That is enough to detect
// death, and reading further ahead means buffering without bound in front of a
// consumer that is by definition not consuming -- the leak this change avoids.
func (s *Session) startCarrierWatch() {
	if s.watch != nil || s.readHeaderLen == len(s.readHeader) {
		return
	}
	watch := make(chan carrierWatch, 1)
	target := s.readHeader[s.readHeaderLen:]
	s.watch = watch
	go func() {
		read, err := s.conn.Read(target)
		if err != nil {
			// Publish the death before handing back the result: whoever readLoop
			// is waiting for is waiting on s.done, not on this channel.
			s.fail(err)
		}
		watch <- carrierWatch{read: read, err: err}
	}()
}

// joinCarrierWatch collects an outstanding read-ahead. It blocks for exactly as
// long as the read it stands in for would have, and every path that ends a
// session closes the carrier, so the watch always completes.
func (s *Session) joinCarrierWatch() (carrierWatch, bool) {
	if s.watch == nil {
		return carrierWatch{}, false
	}
	result := <-s.watch
	s.watch = nil
	s.readHeaderLen += result.read
	return result, true
}

// enqueueWatchingCarrier hands payload to stream without going blind to the
// carrier. enqueueWithTimeout on its own parks readLoop for up to
// StreamStallTimeout, and a peer that dies inside that wait cannot be noticed by
// anyone else: the wait ends early only on a closed s.done, and only readLoop
// closes s.done on carrier death.
func (s *Session) enqueueWatchingCarrier(stream *Stream, payload receiveBuffer) streamEnqueueResult {
	remaining := s.config.StreamStallTimeout
	unwatched := remaining
	if unwatched > carrierWatchDelay || unwatched <= 0 {
		// A zero timeout means "wait forever" to enqueueWithTimeout, so it must
		// never be passed on. validateConfig rejects a non-positive stall timeout
		// today; this keeps that from becoming load-bearing.
		unwatched = carrierWatchDelay
	}
	result := stream.enqueueWithTimeout(payload, unwatched)
	if result != streamEnqueueStalled || remaining <= unwatched {
		return result
	}
	// Still full after carrierWatchDelay: this is a real stall, and readLoop is
	// about to wait out the rest of the stall budget for it. That is worth one
	// goroutine -- and only genuine stalls ever pay for it.
	s.startCarrierWatch()
	return stream.enqueueWithTimeout(payload, remaining-unwatched)
}

func (s *Session) acceptRemoteStream(streamID uint32) {
	s.streamsMu.Lock()
	if _, exists := s.streams[streamID]; exists {
		s.streamsMu.Unlock()
		return
	}
	stream := newStream(s, streamID)
	s.streams[streamID] = stream
	s.streamsMu.Unlock()
	select {
	case s.accepts <- stream:
	case <-s.done:
	}
}

func (s *Session) validInboundFrame(header frameHeader) bool {
	if header.command == frameKeepalive {
		return header.streamID == 0
	}
	if header.streamID == 0 {
		return false
	}
	if header.command != frameOpen {
		return true
	}
	peerUsesOddIDs := !s.client
	return (header.streamID%2 == 1) == peerUsesOddIDs
}

func (s *Session) lookupStream(streamID uint32) *Stream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	return s.streams[streamID]
}

func (s *Session) removeStream(streamID uint32) {
	s.streamsMu.Lock()
	delete(s.streams, streamID)
	s.streamsMu.Unlock()
}

// reserveReceive claims session-wide receive budget, waiting for another stream
// to free some if the session is at its limit.
//
// This wait cannot be watched the way the stream enqueue is: readLoop reaches it
// between a frame header and that frame's payload, so the next bytes on the
// carrier are payload and a read-ahead would consume them into the header
// pushback and desync the connection. A carrier that dies here therefore still
// goes unnoticed -- and unlike the stall this wait has no timeout, so it wedges
// until something frees budget. Closing it means reading the payload before
// reserving for it, which changes when a receive buffer is acquired.
func (s *Session) reserveReceive(size int) bool {
	if size > s.config.MaxReceiveBuffer {
		s.fail(ErrInvalidProtocol)
		return false
	}
	for {
		s.receiveMu.Lock()
		if s.receiveUsed+size <= s.config.MaxReceiveBuffer {
			s.receiveUsed += size
			s.receiveMu.Unlock()
			return true
		}
		changed := s.receiveChanged
		s.receiveMu.Unlock()
		select {
		case <-changed:
		case <-s.done:
			return false
		}
	}
}

func (s *Session) releaseReceive(size int) {
	if size <= 0 {
		return
	}
	s.receiveMu.Lock()
	s.receiveUsed -= size
	if s.receiveUsed < 0 {
		s.receiveUsed = 0
	}
	notify(s.receiveChanged)
	s.receiveMu.Unlock()
}

func (s *Session) fail(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closeOnce.Do(func() {
		s.errorMu.Lock()
		s.lastError = err
		s.errorMu.Unlock()
		// Close done BEFORE taking submitMu. A submitter parked on a full
		// writeQueue holds submitMu and only a closed done can wake it, so
		// acquiring the lock first deadlocks the session permanently (D8):
		// done would never close, the carrier would never be closed, neither
		// loop would exit, and Close would park on loops.Wait forever.
		// lastError is published first so anyone woken by done reports the real
		// cause rather than the generic terminal error.
		close(s.done)
		// Barrier, not a critical section: once every in-flight submitter has
		// left submitWithStateResult, no further frame can reach writeQueue,
		// because later submitters observe the closed done under submitMu and
		// bail. That is the invariant that lets failQueuedWrites drain the
		// queue exactly once below, and it must be established before the
		// carrier is closed.
		s.submitMu.Lock()
		s.submitMu.Unlock()
		_ = s.conn.Close()
		s.receiveMu.Lock()
		notify(s.receiveChanged)
		s.receiveMu.Unlock()
		s.acceptMu.Lock()
		close(s.acceptChanged)
		s.acceptChanged = make(chan struct{})
		s.acceptMu.Unlock()
		s.streamsMu.Lock()
		for _, stream := range s.streams {
			stream.sessionStopped()
			// sessionStopped only flags the stream; whatever it already queued
			// still holds pooled buffers and a slice of the session-wide
			// reservation, and nothing will drain it now that the session is
			// gone. Streams parked in accepts are covered too: acceptRemoteStream
			// registers them here before handing them over.
			// D7/M3: releaseQueued nils chunks under stateMu, so this stays
			// exactly-once against a concurrent Stream.Close. Lock order
			// streamsMu > stateMu > receiveMu holds, so it is safe in place.
			stream.releaseQueued()
		}
		s.streamsMu.Unlock()
	})
}

func (s *Session) terminalError() error {
	s.errorMu.Lock()
	defer s.errorMu.Unlock()
	if s.lastError == nil {
		return io.ErrClosedPipe
	}
	return s.lastError
}

func (s *Session) keepaliveLoop() {
	ticker := time.NewTicker(s.config.KeepAliveInterval)
	defer ticker.Stop()
	result := make(chan error, 1)
	for {
		select {
		case now := <-ticker.C:
			lastReceive := time.Unix(0, s.lastReceive.Load())
			if now.Sub(lastReceive) > s.config.KeepAliveTimeout {
				s.fail(ErrTimeout)
				return
			}
			// A heartbeat is only late once the peer-liveness window expires. Using
			// the (usually much shorter) send interval here makes a healthy session
			// fail merely because the writer or scheduler was delayed for one tick.
			if err := s.submitResult(frameKeepalive, 0, nil, now.Add(s.config.KeepAliveTimeout), result); err != nil {
				s.fail(err)
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) acceptState() (time.Time, <-chan struct{}) {
	s.acceptMu.Lock()
	defer s.acceptMu.Unlock()
	return s.acceptDeadline, s.acceptChanged
}

func deadlineSignal(deadline time.Time) (<-chan time.Time, func()) {
	if deadline.IsZero() {
		return nil, func() {}
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	return timer.C, func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

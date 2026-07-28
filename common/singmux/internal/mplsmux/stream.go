// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

const closeTimeout = 30 * time.Second

type receiveChunk struct {
	buffer receiveBuffer
	offset int
}

type streamEnqueueResult uint8

const (
	streamEnqueueStopped streamEnqueueResult = iota
	streamEnqueueQueued
	streamEnqueueStalled
)

// Stream is one full-duplex logical connection carried by a Session.
type Stream struct {
	session *Session
	id      uint32

	readMu  sync.Mutex
	writeMu sync.Mutex
	stateMu sync.Mutex

	chunks        []receiveChunk
	buffered      int
	localClosed   bool
	remoteClosed  bool
	sessionClosed bool
	readChanged   chan struct{}
	writeChanged  chan struct{}
	bufferChanged chan struct{}
	bufferWaiting bool
	readDeadline  time.Time
	writeDeadline time.Time
	writeResult   chan error
}

func newStream(session *Session, streamID uint32) *Stream {
	return &Stream{
		session:       session,
		id:            streamID,
		readChanged:   make(chan struct{}, 1),
		writeChanged:  make(chan struct{}, 1),
		bufferChanged: make(chan struct{}, 1),
		writeResult:   make(chan error, 1),
	}
}

// ID returns the stream identifier used on the carrier.
func (s *Stream) ID() uint32 {
	return s.id
}

func (s *Stream) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		s.stateMu.Lock()
		if len(s.chunks) > 0 {
			chunk := &s.chunks[0]
			count := copy(destination, chunk.buffer.data(chunk.offset))
			chunk.offset += count
			s.buffered -= count
			var released receiveBuffer
			if chunk.offset == chunk.buffer.Len() {
				released = chunk.buffer
				// Retention hygiene, not double-release protection (D9): the
				// reslice below already excludes this slot from anything
				// drainLocked can return. Without the zeroing the backing array
				// keeps pointing at a buffer that is about to go back to the
				// pool -- indefinitely on the [1:] path, until the next append
				// on the [:0] path.
				s.chunks[0] = receiveChunk{}
				if len(s.chunks) == 1 {
					s.chunks = s.chunks[:0]
				} else {
					s.chunks = s.chunks[1:]
				}
			}
			if s.bufferWaiting {
				s.bufferWaiting = false
				notify(s.bufferChanged)
			}
			s.stateMu.Unlock()
			s.session.releaseReceive(count)
			if !released.IsEmpty() {
				releaseReceiveBuffer(released)
			}
			return count, nil
		}
		if s.localClosed {
			s.stateMu.Unlock()
			return 0, io.ErrClosedPipe
		}
		if s.remoteClosed {
			s.stateMu.Unlock()
			return 0, io.EOF
		}
		if s.sessionClosed {
			s.stateMu.Unlock()
			return 0, s.session.terminalError()
		}
		changed := s.readChanged
		deadline := s.readDeadline
		s.stateMu.Unlock()

		deadlineChannel, stopTimer := deadlineSignal(deadline)
		select {
		case <-changed:
			stopTimer()
		case <-deadlineChannel:
			stopTimer()
			return 0, ErrTimeout
		case <-s.session.done:
			stopTimer()
		}
	}
}

// ReadMultiBuffer transfers the next complete receive frame to Xray's buffer
// pipeline. Unlike an io.Reader adapter, it does not allocate a second payload
// buffer before an idle stream becomes readable.
func (s *Stream) ReadMultiBuffer() (buf.MultiBuffer, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		s.stateMu.Lock()
		if len(s.chunks) > 0 {
			chunk := s.chunks[0]
			count := chunk.buffer.Len() - chunk.offset
			// Retention hygiene, not double-release protection (D9): ownership
			// passes to the returned MultiBuffer, and the reslice below already
			// excludes this slot from anything drainLocked can return. The
			// zeroing stops the backing array from pinning a buffer the caller
			// now owns.
			s.chunks[0] = receiveChunk{}
			if len(s.chunks) == 1 {
				s.chunks = s.chunks[:0]
			} else {
				s.chunks = s.chunks[1:]
			}
			s.buffered -= count
			if s.bufferWaiting {
				s.bufferWaiting = false
				notify(s.bufferChanged)
			}
			s.stateMu.Unlock()
			s.session.releaseReceive(count)
			return chunk.buffer.multiBuffer(chunk.offset), nil
		}
		if s.localClosed {
			s.stateMu.Unlock()
			return nil, io.ErrClosedPipe
		}
		if s.remoteClosed {
			s.stateMu.Unlock()
			return nil, io.EOF
		}
		if s.sessionClosed {
			s.stateMu.Unlock()
			return nil, s.session.terminalError()
		}
		changed := s.readChanged
		deadline := s.readDeadline
		s.stateMu.Unlock()

		deadlineChannel, stopTimer := deadlineSignal(deadline)
		select {
		case <-changed:
			stopTimer()
		case <-deadlineChannel:
			stopTimer()
			return nil, ErrTimeout
		case <-s.session.done:
			stopTimer()
		}
	}
}

func (s *Stream) Write(source []byte) (int, error) {
	if len(source) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	written := 0
	for len(source) > 0 {
		frameSize := len(source)
		if frameSize > s.session.config.MaxFrameSize {
			frameSize = s.session.config.MaxFrameSize
		}
		if err := s.session.submitWithStateResult(frameData, s.id, source[:frameSize], s.writeState, s.writeResult); err != nil {
			if err == ErrTimeout {
				// The timed-out carrier write may still complete asynchronously.
				// Retire its completion channel instead of consuming that stale result
				// in a later Write.
				s.writeResult = make(chan error, 1)
			}
			return written, err
		}
		written += frameSize
		source = source[frameSize:]
	}
	return written, nil
}

func (s *Stream) writeState() (time.Time, <-chan struct{}, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch {
	case s.localClosed:
		return s.writeDeadline, s.writeChanged, io.ErrClosedPipe
	case s.remoteClosed:
		return s.writeDeadline, s.writeChanged, io.EOF
	case s.sessionClosed:
		return s.writeDeadline, s.writeChanged, s.session.terminalError()
	default:
		return s.writeDeadline, s.writeChanged, nil
	}
}

func (s *Stream) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.stateMu.Lock()
	if s.localClosed {
		s.stateMu.Unlock()
		return io.ErrClosedPipe
	}
	s.localClosed = true
	queued, queuedBytes := s.drainLocked()
	deadline := s.writeDeadline
	signalDeadline := time.Now().Add(closeTimeout)
	if deadline.IsZero() || signalDeadline.Before(deadline) {
		deadline = signalDeadline
	}
	s.notifyAllLocked()
	s.stateMu.Unlock()

	for _, chunk := range queued {
		releaseReceiveBuffer(chunk.buffer)
	}
	s.session.releaseReceive(queuedBytes)

	err := s.session.submitResult(frameClose, s.id, nil, deadline, s.writeResult)
	s.session.removeStream(s.id)
	if s.session.IsClosed() {
		return nil
	}
	return err
}

func (s *Stream) LocalAddr() net.Addr  { return s.session.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.session.RemoteAddr() }

func (s *Stream) SetDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	s.readDeadline = deadline
	s.writeDeadline = deadline
	notify(s.readChanged)
	notify(s.writeChanged)
	s.stateMu.Unlock()
	return nil
}

func (s *Stream) SetReadDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	s.readDeadline = deadline
	notify(s.readChanged)
	s.stateMu.Unlock()
	return nil
}

func (s *Stream) SetWriteDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	s.writeDeadline = deadline
	notify(s.writeChanged)
	s.stateMu.Unlock()
	return nil
}

func (s *Stream) enqueue(buffer receiveBuffer) bool {
	return s.enqueueWithTimeout(buffer, 0) == streamEnqueueQueued
}

func (s *Stream) enqueueWithTimeout(buffer receiveBuffer, timeout time.Duration) streamEnqueueResult {
	bufferSize := buffer.Len()
	var timeoutChannel <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.stateMu.Lock()
		if s.localClosed || s.remoteClosed || s.sessionClosed {
			s.stateMu.Unlock()
			return streamEnqueueStopped
		}
		if s.buffered+bufferSize <= s.session.config.MaxStreamBuffer {
			s.chunks = append(s.chunks, receiveChunk{buffer: buffer})
			s.buffered += bufferSize
			notify(s.readChanged)
			s.stateMu.Unlock()
			return streamEnqueueQueued
		}
		s.bufferWaiting = true
		changed := s.bufferChanged
		s.stateMu.Unlock()
		if timer == nil && timeout > 0 {
			timer = time.NewTimer(timeout)
			timeoutChannel = timer.C
		}
		select {
		case <-changed:
		case <-s.session.done:
			return streamEnqueueStopped
		case <-timeoutChannel:
			return streamEnqueueStalled
		}
	}
}

func (s *Stream) closeOnReceiveOverflow() ([]receiveChunk, int, bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.localClosed {
		return nil, 0, false
	}
	s.localClosed = true
	queued, queuedBytes := s.drainLocked()
	s.notifyAllLocked()
	return queued, queuedBytes, true
}

// Abort discards unread data and schedules a close frame without waiting for
// the carrier writer. It is used by bounded server admission and receive-stall
// cleanup paths where blocking the carrier would retain unrelated streams.
func (s *Stream) Abort() error {
	queued, queuedBytes, closed := s.closeOnReceiveOverflow()
	for _, chunk := range queued {
		releaseReceiveBuffer(chunk.buffer)
	}
	s.session.releaseReceive(queuedBytes)
	if !closed {
		return nil
	}
	s.session.removeStream(s.id)
	if s.session.IsClosed() {
		return nil
	}
	if s.session.trySubmitControl(frameClose, s.id) {
		return nil
	}
	s.session.fail(ErrControlQueueFull)
	return ErrControlQueueFull
}

// releaseQueued hands back everything still queued on this stream: the pooled
// receive buffers and the session-wide reservation they hold.
//
// Session teardown needs this. Marking a stream closed leaves its queue intact,
// and nothing else will ever drain it once the owner is gone -- the buffers are
// pooled so GC still reclaims them, but the reservation is never decremented,
// and a saturated MaxReceiveBuffer blocks every later reserve on that session.
//
// D7/M3: drainLocked nils s.chunks under stateMu, so ownership transfers here
// exactly once and repeat calls are no-ops. Releasing happens outside stateMu --
// releaseReceive takes receiveMu, and the lock order is stateMu > receiveMu.
func (s *Stream) releaseQueued() {
	s.stateMu.Lock()
	queued, queuedBytes := s.drainLocked()
	// Freeing the queue can admit a sender parked in enqueueWithTimeout, exactly
	// as Read does. Teardown callers have usually notified already via
	// sessionStopped, but doing it here too means releaseQueued carries no
	// ordering precondition for its callers.
	if s.bufferWaiting {
		s.bufferWaiting = false
		notify(s.bufferChanged)
	}
	s.stateMu.Unlock()

	for _, chunk := range queued {
		releaseReceiveBuffer(chunk.buffer)
	}
	s.session.releaseReceive(queuedBytes)
}

func (s *Stream) remoteStopped() {
	s.stateMu.Lock()
	s.remoteClosed = true
	s.notifyAllLocked()
	s.stateMu.Unlock()
}

func (s *Stream) sessionStopped() {
	s.stateMu.Lock()
	s.sessionClosed = true
	s.notifyAllLocked()
	s.stateMu.Unlock()
}

func (s *Stream) drainLocked() ([]receiveChunk, int) {
	chunks := s.chunks
	bytes := s.buffered
	s.chunks = nil
	s.buffered = 0
	return chunks, bytes
}

func (s *Stream) notifyAllLocked() {
	notify(s.readChanged)
	notify(s.writeChanged)
	notify(s.bufferChanged)
}

func notify(channel chan<- struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

var _ net.Conn = (*Stream)(nil)

// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"io"
	"net"
	"sync"
	"time"
)

const closeTimeout = 30 * time.Second

type receiveChunk struct {
	buffer []byte
	offset int
}

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
	readDeadline  time.Time
	writeDeadline time.Time
}

func newStream(session *Session, streamID uint32) *Stream {
	return &Stream{
		session:       session,
		id:            streamID,
		readChanged:   make(chan struct{}, 1),
		writeChanged:  make(chan struct{}, 1),
		bufferChanged: make(chan struct{}, 1),
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
			count := copy(destination, chunk.buffer[chunk.offset:])
			chunk.offset += count
			s.buffered -= count
			var released []byte
			if chunk.offset == len(chunk.buffer) {
				released = chunk.buffer
				s.chunks[0] = receiveChunk{}
				if len(s.chunks) == 1 {
					s.chunks = s.chunks[:0]
				} else {
					s.chunks = s.chunks[1:]
				}
			}
			notify(s.bufferChanged)
			s.stateMu.Unlock()
			s.session.releaseReceive(count)
			if released != nil {
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
		if err := s.session.submitWithState(frameData, s.id, source[:frameSize], s.writeState); err != nil {
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

	err := s.session.submit(frameClose, s.id, nil, deadline)
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

func (s *Stream) enqueue(buffer []byte) bool {
	for {
		s.stateMu.Lock()
		if s.localClosed || s.remoteClosed || s.sessionClosed {
			s.stateMu.Unlock()
			return false
		}
		if s.buffered+len(buffer) <= s.session.config.MaxStreamBuffer {
			s.chunks = append(s.chunks, receiveChunk{buffer: buffer})
			s.buffered += len(buffer)
			notify(s.readChanged)
			s.stateMu.Unlock()
			return true
		}
		changed := s.bufferChanged
		s.stateMu.Unlock()
		select {
		case <-changed:
		case <-s.session.done:
			return false
		}
	}
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

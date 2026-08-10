// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type h2ClientSession struct {
	connection net.Conn
	client     *http2.ClientConn
}

func newH2ClientSession(connection net.Conn) (*h2ClientSession, error) {
	client, err := (&http2.Transport{}).NewClientConn(connection)
	if err != nil {
		return nil, err
	}
	return &h2ClientSession{connection: connection, client: client}, nil
}

func (s *h2ClientSession) OpenStream(ctx context.Context, accounted func()) (net.Conn, error) {
	if !s.client.ReserveNewRequest() {
		// ponytail: http2 exposes no capacity notification; poll until a stream slot opens.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !s.client.ReserveNewRequest() {
			state := s.client.State()
			if state.Closed || state.Closing {
				return nil, net.ErrClosed
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
			}
		}
	}
	accounted()
	requestReader, requestWriter := io.Pipe()
	streamContext, cancel := context.WithCancel(ctx)
	body := &h2RequestBody{reader: requestReader, started: make(chan struct{})}
	request := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: "localhost"},
		Host:   "localhost",
		Header: make(http.Header),
		Body:   body,
	}).WithContext(streamContext)
	response := &h2Response{done: make(chan struct{})}
	go func() {
		response.response, response.err = s.client.RoundTrip(request)
		close(response.done)
	}()
	select {
	case <-response.done:
		if err := response.prepare(); err != nil {
			cancel()
			_ = requestWriter.CloseWithError(err)
			_ = body.Close()
			return nil, err
		}
	case <-body.started:
		if err := ctx.Err(); err != nil {
			cancel()
			_ = requestWriter.CloseWithError(err)
			_ = body.Close()
			_ = response.Close()
			return nil, err
		}
	case <-ctx.Done():
		cancel()
		_ = requestWriter.CloseWithError(ctx.Err())
		_ = body.Close()
		_ = response.Close()
		return nil, ctx.Err()
	}
	return &h2ClientStream{
		reader:     response,
		writer:     requestWriter,
		cancel:     cancel,
		localAddr:  s.connection.LocalAddr(),
		remoteAddr: s.connection.RemoteAddr(),
	}, nil
}

type h2RequestBody struct {
	reader  *io.PipeReader
	started chan struct{}
	once    sync.Once
}

func (b *h2RequestBody) Read(payload []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.reader.Read(payload)
}

func (b *h2RequestBody) Close() error {
	b.once.Do(func() { close(b.started) })
	return b.reader.Close()
}

type h2Response struct {
	done     chan struct{}
	response *http.Response
	err      error
	once     sync.Once
	reader   io.ReadCloser
	readyErr error
}

func (r *h2Response) prepare() error {
	r.once.Do(func() {
		<-r.done
		if r.err != nil {
			if r.response != nil && r.response.Body != nil {
				_ = r.response.Body.Close()
			}
			r.readyErr = r.err
			return
		}
		if r.response.StatusCode != http.StatusOK {
			r.readyErr = fmt.Errorf("h2mux CONNECT returned HTTP status %d", r.response.StatusCode)
			_ = r.response.Body.Close()
			return
		}
		r.reader = r.response.Body
	})
	return r.readyErr
}

func (r *h2Response) Read(payload []byte) (int, error) {
	if err := r.prepare(); err != nil {
		return 0, err
	}
	return r.reader.Read(payload)
}

func (r *h2Response) Close() error {
	if err := r.prepare(); err != nil {
		return nil
	}
	return r.reader.Close()
}

func (s *h2ClientSession) NumStreams() int {
	state := s.client.State()
	return state.StreamsActive + state.StreamsReserved + state.StreamsPending
}

func (s *h2ClientSession) IsClosed() bool {
	state := s.client.State()
	return state.Closed || state.Closing
}

func (s *h2ClientSession) Close() error {
	return s.client.Close()
}

type h2ClientStream struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr
	closeOnce  sync.Once
	closeErr   error

	deadlineMu      sync.Mutex
	readTimer       *time.Timer
	writeTimer      *time.Timer
	readGeneration  uint64
	writeGeneration uint64
	readExpired     bool
	writeExpired    bool
}

func (s *h2ClientStream) Read(payload []byte) (int, error) {
	count, err := s.reader.Read(payload)
	s.deadlineMu.Lock()
	expired := s.readExpired
	s.deadlineMu.Unlock()
	if err != nil && expired {
		return count, os.ErrDeadlineExceeded
	}
	return count, err
}

func (s *h2ClientStream) Write(payload []byte) (int, error) {
	count, err := s.writer.Write(payload)
	s.deadlineMu.Lock()
	expired := s.writeExpired
	s.deadlineMu.Unlock()
	if err != nil && expired {
		return count, os.ErrDeadlineExceeded
	}
	return count, err
}

func (s *h2ClientStream) CloseWrite() error {
	return s.writer.Close()
}

func (s *h2ClientStream) Close() error {
	s.closeOnce.Do(func() {
		s.stopDeadlines()
		s.cancel()
		s.closeErr = errors.Join(s.writer.Close(), s.reader.Close())
	})
	return s.closeErr
}

func (s *h2ClientStream) LocalAddr() net.Addr  { return s.localAddr }
func (s *h2ClientStream) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *h2ClientStream) SetDeadline(deadline time.Time) error {
	_ = s.SetReadDeadline(deadline)
	return s.SetWriteDeadline(deadline)
}

func (s *h2ClientStream) SetReadDeadline(deadline time.Time) error {
	s.deadlineMu.Lock()
	s.readGeneration++
	generation := s.readGeneration
	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	s.readExpired = false
	delay := time.Until(deadline)
	if deadline.IsZero() {
		s.deadlineMu.Unlock()
		return nil
	}
	if delay > 0 {
		s.readTimer = time.AfterFunc(delay, func() { s.expireRead(generation) })
		s.deadlineMu.Unlock()
		return nil
	}
	s.readExpired = true
	// ponytail: HTTP/2 has no per-stream deadline API; a read timeout discards this stream.
	s.cancel()
	s.deadlineMu.Unlock()
	return nil
}

func (s *h2ClientStream) SetWriteDeadline(deadline time.Time) error {
	s.deadlineMu.Lock()
	s.writeGeneration++
	generation := s.writeGeneration
	if s.writeTimer != nil {
		s.writeTimer.Stop()
		s.writeTimer = nil
	}
	s.writeExpired = false
	delay := time.Until(deadline)
	if deadline.IsZero() {
		s.deadlineMu.Unlock()
		return nil
	}
	if delay > 0 {
		s.writeTimer = time.AfterFunc(delay, func() { s.expireWrite(generation) })
		s.deadlineMu.Unlock()
		return nil
	}
	s.writeExpired = true
	_ = s.writer.CloseWithError(os.ErrDeadlineExceeded)
	s.deadlineMu.Unlock()
	return nil
}

func (s *h2ClientStream) expireRead(generation uint64) {
	s.deadlineMu.Lock()
	if generation != s.readGeneration {
		s.deadlineMu.Unlock()
		return
	}
	s.readTimer = nil
	s.readExpired = true
	s.cancel()
	s.deadlineMu.Unlock()
}

func (s *h2ClientStream) expireWrite(generation uint64) {
	s.deadlineMu.Lock()
	if generation != s.writeGeneration {
		s.deadlineMu.Unlock()
		return
	}
	s.writeTimer = nil
	s.writeExpired = true
	_ = s.writer.CloseWithError(os.ErrDeadlineExceeded)
	s.deadlineMu.Unlock()
}

func (s *h2ClientStream) stopDeadlines() {
	s.deadlineMu.Lock()
	s.readGeneration++
	s.writeGeneration++
	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}
	if s.writeTimer != nil {
		s.writeTimer.Stop()
		s.writeTimer = nil
	}
	s.deadlineMu.Unlock()
}

// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSessionPair(t *testing.T, configure func(*Config)) (*Session, *Session) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	if configure != nil {
		configure(config)
	}
	client, err := Client(clientConn, config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := Server(serverConn, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

type delayedReadCloseConnection struct {
	readStarted     chan struct{}
	closeCalled     chan struct{}
	allowReadReturn chan struct{}
	readStartedOnce sync.Once
	closeOnce       sync.Once
}

func newDelayedReadCloseConnection() *delayedReadCloseConnection {
	return &delayedReadCloseConnection{
		readStarted:     make(chan struct{}),
		closeCalled:     make(chan struct{}),
		allowReadReturn: make(chan struct{}),
	}
}

func (c *delayedReadCloseConnection) Read([]byte) (int, error) {
	c.readStartedOnce.Do(func() { close(c.readStarted) })
	<-c.allowReadReturn
	return 0, io.EOF
}

func (*delayedReadCloseConnection) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (c *delayedReadCloseConnection) Close() error {
	c.closeOnce.Do(func() { close(c.closeCalled) })
	return nil
}

func TestSessionCloseWaitsForCarrierLoops(t *testing.T) {
	connection := newDelayedReadCloseConnection()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-connection.readStarted:
	case <-time.After(time.Second):
		t.Fatal("carrier read loop did not start")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- session.Close() }()
	select {
	case <-connection.closeCalled:
	case <-time.After(time.Second):
		t.Fatal("session close did not close the carrier")
	}

	returnedBeforeReadLoop := false
	var closeErr error
	select {
	case closeErr = <-closeResult:
		returnedBeforeReadLoop = true
	case <-time.After(100 * time.Millisecond):
	}
	close(connection.allowReadReturn)
	if !returnedBeforeReadLoop {
		select {
		case closeErr = <-closeResult:
		case <-time.After(time.Second):
			t.Fatal("session close did not finish after the carrier read returned")
		}
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if returnedBeforeReadLoop {
		t.Fatal("session Close returned while its carrier read loop was still running")
	}
}

func TestSessionRoundTripAndStreamIDs(t *testing.T) {
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if clientStream.ID() != 3 || serverStream.ID() != 3 {
		t.Fatalf("client/server stream IDs = %d/%d, want 3/3", clientStream.ID(), serverStream.ID())
	}

	request := []byte("client request")
	if _, err := clientStream.Write(request); err != nil {
		t.Fatal(err)
	}
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(serverStream, gotRequest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("server received %q, want %q", gotRequest, request)
	}

	response := []byte("server response")
	if _, err := serverStream.Write(response); err != nil {
		t.Fatal(err)
	}
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(clientStream, gotResponse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("client received %q, want %q", gotResponse, response)
	}

	serverOpened, err := server.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	clientAccepted, err := client.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if serverOpened.ID() != 2 || clientAccepted.ID() != 2 {
		t.Fatalf("server/client stream IDs = %d/%d, want 2/2", serverOpened.ID(), clientAccepted.ID())
	}
}

func TestSessionConcurrentFullDuplexStreams(t *testing.T) {
	client, server := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = 8 * 1024
		config.MaxStreamBuffer = 32 * 1024
		config.MaxReceiveBuffer = 512 * 1024
	})
	const (
		streamCount = 64
		payloadSize = 256 * 1024
	)
	payload := bytes.Repeat([]byte("mpl-smux"), payloadSize/len("mpl-smux"))

	serverErrors := make(chan error, streamCount)
	go func() {
		var workers sync.WaitGroup
		for range streamCount {
			stream, err := server.AcceptStream()
			if err != nil {
				serverErrors <- err
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer stream.Close()
				streamID := stream.ID()
				writeResult := make(chan error, 1)
				go func() {
					_, err := stream.Write(payload)
					if err != nil {
						err = fmt.Errorf("server stream %d write: %w", streamID, err)
					}
					writeResult <- err
				}()
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, received); err != nil {
					serverErrors <- fmt.Errorf("server stream %d read: %w", streamID, err)
					return
				}
				if !bytes.Equal(received, payload) {
					serverErrors <- errors.New("server payload mismatch")
					return
				}
				serverErrors <- <-writeResult
			}()
		}
		workers.Wait()
	}()

	clientErrors := make(chan error, streamCount)
	var clients sync.WaitGroup
	for range streamCount {
		stream, err := client.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer stream.Close()
			streamID := stream.ID()
			writeResult := make(chan error, 1)
			go func() {
				_, err := stream.Write(payload)
				if err != nil {
					err = fmt.Errorf("client stream %d write: %w", streamID, err)
				}
				writeResult <- err
			}()
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, received); err != nil {
				clientErrors <- fmt.Errorf("client stream %d read: %w", streamID, err)
				return
			}
			if !bytes.Equal(received, payload) {
				clientErrors <- errors.New("client payload mismatch")
				return
			}
			clientErrors <- <-writeResult
		}()
	}
	clients.Wait()
	for range streamCount {
		if err := <-clientErrors; err != nil {
			t.Fatal(err)
		}
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadAndAcceptDeadlines(t *testing.T) {
	client, server := testSessionPair(t, nil)
	deadline := time.Now().Add(30 * time.Millisecond)
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := server.AcceptStream(); !errors.Is(err, ErrTimeout) {
		t.Fatalf("AcceptStream error = %v, want %v", err, ErrTimeout)
	}
	if err := server.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientStream.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientStream.Read(make([]byte, 1)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Read error = %v, want %v", err, ErrTimeout)
	}
	if err := clientStream.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := serverStream.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	if _, err := io.ReadFull(clientStream, value[:]); err != nil || value[0] != 42 {
		t.Fatalf("ReadFull = %v, %v", value, err)
	}
}

func TestAcceptStreamDoesNotReturnBacklogAfterSessionClose(t *testing.T) {
	for range 128 {
		session := &Session{
			accepts:       make(chan *Stream, 1),
			done:          make(chan struct{}),
			acceptChanged: make(chan struct{}),
		}
		session.accepts <- &Stream{}
		close(session.done)

		stream, err := session.AcceptStream()
		if stream != nil || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("AcceptStream after Close = (%v, %v), want (nil, %v)", stream, err, io.ErrClosedPipe)
		}
	}
}

func TestRemoteCloseDeliversBufferedDataThenEOF(t *testing.T) {
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverStream.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	if err := serverStream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "final" {
		t.Fatalf("received %q, want final", got)
	}
}

func TestCarrierFailureUnblocksStream(t *testing.T) {
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.AcceptStream(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := clientStream.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read succeeded after carrier failure")
	}
}

func TestInvalidRemoteOpenParityClosesSession(t *testing.T) {
	local, remote := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	server, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = remote.Close()
	})
	var encoded [frameHeaderSize]byte
	encodeFrameHeader(&encoded, frameOpen, 2, 0)
	if _, err := remote.Write(encoded[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.CloseChan():
		if !errors.Is(server.terminalError(), ErrInvalidProtocol) {
			t.Fatalf("terminal error = %v, want %v", server.terminalError(), ErrInvalidProtocol)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not reject invalid stream parity")
	}
}

func TestConfigValidationAndTimeoutError(t *testing.T) {
	if _, err := Client(nil, nil); err == nil {
		t.Fatal("Client accepted a nil connection")
	}
	tests := map[string]func(*Config){
		"version":              func(config *Config) { config.Version = 2 },
		"zero frame":           func(config *Config) { config.MaxFrameSize = 0 },
		"oversized frame":      func(config *Config) { config.MaxFrameSize = maxFramePayload + 1 },
		"receive below frame":  func(config *Config) { config.MaxReceiveBuffer = config.MaxFrameSize - 1 },
		"stream below frame":   func(config *Config) { config.MaxStreamBuffer = config.MaxFrameSize - 1 },
		"stream above receive": func(config *Config) { config.MaxStreamBuffer = config.MaxReceiveBuffer + 1 },
		"keepalive interval":   func(config *Config) { config.KeepAliveInterval = 0 },
		"keepalive timeout":    func(config *Config) { config.KeepAliveTimeout = config.KeepAliveInterval / 2 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			config := DefaultConfig()
			mutate(config)
			if _, err := Client(left, config); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
	if ErrTimeout.Error() == "" || !ErrTimeout.Timeout() || !ErrTimeout.Temporary() {
		t.Fatal("timeout error does not implement net.Error semantics")
	}
}

func TestGenericAliasesCountsAddressesAndDeadlines(t *testing.T) {
	client, server := testSessionPair(t, nil)
	opened, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	clientStream := opened.(*Stream)
	serverStream := accepted.(*Stream)
	if client.NumStreams() != 1 || server.NumStreams() != 1 {
		t.Fatalf("stream counts = %d/%d, want 1/1", client.NumStreams(), server.NumStreams())
	}
	if client.LocalAddr() == nil || client.RemoteAddr() == nil || clientStream.LocalAddr() == nil || clientStream.RemoteAddr() == nil {
		t.Fatal("net.Pipe addresses were not forwarded")
	}
	deadline := time.Now().Add(time.Second)
	if err := clientStream.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientStream.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if count, err := clientStream.Read(nil); count != 0 || err != nil {
		t.Fatalf("zero Read = %d, %v", count, err)
	}
	if count, err := clientStream.Write(nil); count != 0 || err != nil {
		t.Fatalf("zero Write = %d, %v", count, err)
	}
	if err := clientStream.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(clientStream.Close(), io.ErrClosedPipe) {
		t.Fatal("second Close did not report a closed stream")
	}
	_ = serverStream.Close()
	_ = client.Close()
	if client.NumStreams() != 0 || !client.IsClosed() {
		t.Fatal("closed session still reports live streams")
	}
}

func TestKeepaliveActivityAndTimeout(t *testing.T) {
	client, server := testSessionPair(t, func(config *Config) {
		config.KeepAliveDisabled = false
		config.KeepAliveInterval = 5 * time.Millisecond
		config.KeepAliveTimeout = 50 * time.Millisecond
	})
	time.Sleep(20 * time.Millisecond)
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("active keepalive pair closed")
	}

	local, remote := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveInterval = 5 * time.Millisecond
	config.KeepAliveTimeout = 15 * time.Millisecond
	timedOut, err := Client(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = timedOut.Close()
		_ = remote.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	select {
	case <-timedOut.CloseChan():
		if !errors.Is(timedOut.terminalError(), ErrTimeout) {
			t.Fatalf("terminal error = %v, want timeout", timedOut.terminalError())
		}
	case <-time.After(time.Second):
		t.Fatal("silent peer did not trigger keepalive timeout")
	}
}

func TestPerStreamReceiveLimitAppliesBackpressure(t *testing.T) {
	_, server := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = 1024
		config.MaxStreamBuffer = 1024
		config.MaxReceiveBuffer = 2048
	})
	stream := newStream(server, 3)
	first := acquireReceiveBuffer(1024)
	second := acquireReceiveBuffer(1024)
	if !server.reserveReceive(len(first)) || !stream.enqueue(first) {
		t.Fatal("first frame was not queued")
	}
	if !server.reserveReceive(len(second)) {
		t.Fatal("second frame did not reserve session capacity")
	}
	queued := make(chan bool, 1)
	go func() { queued <- stream.enqueue(second) }()
	select {
	case <-queued:
		t.Fatal("second frame bypassed the per-stream receive limit")
	case <-time.After(20 * time.Millisecond):
	}
	buffer := make([]byte, 1024)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-queued:
		if !ok {
			t.Fatal("second frame was rejected after capacity became available")
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not release per-stream capacity")
	}
	if _, err := io.ReadFull(stream, buffer); err != nil {
		t.Fatal(err)
	}
}

type blockingWriteConn struct {
	writes  atomic.Int32
	blocked chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingWriteConn() *blockingWriteConn {
	return &blockingWriteConn{blocked: make(chan struct{}), closed: make(chan struct{})}
}

func (c *blockingWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingWriteConn) Write(payload []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		return len(payload), nil
	}
	c.once.Do(func() { close(c.blocked) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingWriteConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func TestSetWriteDeadlineUnblocksActiveWrite(t *testing.T) {
	connection := newBlockingWriteConn()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Client(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("blocked"))
		result <- err
	}()
	select {
	case <-connection.blocked:
	case <-time.After(time.Second):
		t.Fatal("carrier write did not block")
	}
	if err := stream.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("Write error = %v, want %v", err, ErrTimeout)
		}
	case <-time.After(time.Second):
		_ = session.Close()
		<-result
		t.Fatal("SetWriteDeadline did not unblock the active Write")
	}
}

// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type resumedWriteConn struct {
	writes int
	resume chan struct{}
	closed chan struct{}
	close  sync.Once
}

func (c *resumedWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *resumedWriteConn) Write(payload []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return len(payload), nil
	}
	select {
	case <-c.resume:
		return len(payload), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *resumedWriteConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return nil
}

func TestNegotiatedHalfCloseTimeoutDoesNotBlockSiblingStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connection := &resumedWriteConn{resume: make(chan struct{}), closed: make(chan struct{})}
		config := DefaultConfig()
		config.KeepAliveDisabled = true
		config.LogicalHalfClose = true
		session, err := Client(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		stream, err := session.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := stream.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := stream.CloseWrite(); !errors.Is(err, ErrTimeout) {
				t.Fatalf("CloseWrite = %v, want timeout", err)
			}
		}
		close(connection.resume)
		synctest.Wait()
		siblingResult := make(chan error, 1)
		go func() {
			sibling, err := session.OpenStream()
			if err == nil {
				_, err = sibling.Write([]byte("sibling remains usable"))
			}
			siblingResult <- err
		}()
		select {
		case err := <-siblingResult:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			// Rescue the blocked result publisher on the failing implementation
			// so the session can still join its goroutines during cleanup.
			select {
			case <-stream.writeResult:
			default:
			}
			<-siblingResult
			t.Error("timed-out half-closes blocked an unrelated stream after the carrier resumed")
		}
	})
}

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

func TestStreamReadMultiBufferTransfersCompleteFrame(t *testing.T) {
	for _, payloadSize := range []int{8 * 1024, 32 * 1024} {
		t.Run(fmt.Sprintf("%d", payloadSize), func(t *testing.T) {
			client, server := testSessionPair(t, func(config *Config) {
				config.MaxFrameSize = payloadSize
			})
			clientStream, err := client.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			serverStream, err := server.AcceptStream()
			if err != nil {
				t.Fatal(err)
			}

			payload := bytes.Repeat([]byte{0x5a}, payloadSize)
			writeResult := make(chan error, 1)
			go func() {
				_, writeErr := clientStream.Write(payload)
				writeResult <- writeErr
			}()

			multiBuffer, err := serverStream.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(multiBuffer)
			if multiBuffer.Len() != int32(len(payload)) {
				t.Fatalf("received %d bytes, want %d", multiBuffer.Len(), len(payload))
			}
			received := make([]byte, len(payload))
			if copied := multiBuffer.Copy(received); copied != len(received) {
				t.Fatalf("copied %d bytes, want %d", copied, len(received))
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("multi-buffer payload mismatch")
			}
			if err := <-writeResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamReadMultiBufferPreservesPartiallyReadFrame(t *testing.T) {
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 8*1024)
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := clientStream.Write(payload)
		writeResult <- writeErr
	}()

	prefix := make([]byte, 127)
	if _, err := io.ReadFull(serverStream, prefix); err != nil {
		t.Fatal(err)
	}
	multiBuffer, err := serverStream.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(multiBuffer)
	if multiBuffer.Len() != int32(len(payload)-len(prefix)) {
		t.Fatalf("remaining bytes = %d, want %d", multiBuffer.Len(), len(payload)-len(prefix))
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
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

func TestDefaultConfigSlowStreamDoesNotBlockNextStream(t *testing.T) {
	client, server := testSessionPair(t, nil)
	slowClient, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	slowServer, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 3*DefaultConfig().MaxFrameSize)
	if _, err := slowClient.Write(payload); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		healthyClient, err := client.OpenStream()
		if err != nil {
			result <- err
			return
		}
		defer healthyClient.Close()
		healthyServer, err := server.AcceptStream()
		if err != nil {
			result <- err
			return
		}
		defer healthyServer.Close()
		if _, err := healthyClient.Write([]byte("healthy")); err != nil {
			result <- err
			return
		}
		response := make([]byte, len("healthy"))
		_, err = io.ReadFull(healthyServer, response)
		if err == nil && string(response) != "healthy" {
			err = fmt.Errorf("healthy stream payload = %q", response)
		}
		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		if _, err := io.ReadFull(slowServer, make([]byte, len(payload))); err != nil {
			t.Fatal(err)
		}
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("healthy stream stayed blocked after draining the slow stream")
		}
		t.Fatal("slow stream blocked an independent stream")
	}
}

func TestDefaultConfigLeavesFrameHeadroomForStallAbort(t *testing.T) {
	config := DefaultConfig()
	if config.MaxStreamBuffer+maxFramePayload > config.MaxReceiveBuffer {
		t.Fatalf("stream buffer %d leaves less than one %d-byte wire frame in the %d-byte receive window", config.MaxStreamBuffer, maxFramePayload, config.MaxReceiveBuffer)
	}
}

func TestDefaultConfigBoundsPerStreamReceiveShare(t *testing.T) {
	if got := DefaultConfig().MaxStreamBuffer; got > 256*1024 {
		t.Fatalf("default stream buffer = %d, want at most 256 KiB", got)
	}
}

func TestReceiveReservationFinishesFrameAfterHeader(t *testing.T) {
	session := &Session{
		config:         *DefaultConfig(),
		done:           make(chan struct{}),
		receiveChanged: make(chan struct{}, 1),
		receiveUsed:    DefaultConfig().MaxReceiveBuffer,
	}
	reserved := make(chan bool, 1)
	go func() { reserved <- session.reserveReceive(maxFramePayload) }()
	select {
	case ok := <-reserved:
		if !ok {
			t.Fatal("valid wire frame reservation was rejected")
		}
	case <-time.After(100 * time.Millisecond):
		session.releaseReceive(session.receiveUsed)
		<-reserved
		t.Fatal("frame reservation blocked after its header was consumed")
	}
	if want := session.config.MaxReceiveBuffer + maxFramePayload; session.receiveUsed != want {
		t.Fatalf("receive reservation = %d, want bounded frame overshoot %d", session.receiveUsed, want)
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

func TestAcceptStreamSkipsAbortedBacklogStream(t *testing.T) {
	session := &Session{
		streams:       make(map[uint32]*Stream),
		accepts:       make(chan *Stream, 2),
		done:          make(chan struct{}),
		acceptChanged: make(chan struct{}),
	}
	aborted := newStream(session, 1)
	healthy := newStream(session, 3)
	session.streams[healthy.id] = healthy
	session.accepts <- aborted
	session.accepts <- healthy

	accepted, err := session.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream after backlog abort: %v", err)
	}
	if accepted != healthy {
		t.Fatalf("AcceptStream returned %p, want healthy stream %p", accepted, healthy)
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

func TestNegotiatedHalfClosePreservesReverseDirection(t *testing.T) {
	client, server := testSessionPair(t, func(config *Config) { config.LogicalHalfClose = true })
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer clientStream.Close()
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer serverStream.Close()
	if _, err := clientStream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(serverStream)
	if err != nil || string(request) != "request" {
		t.Fatalf("request = (%q, %v), want (request, nil)", request, err)
	}
	if _, err := serverStream.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := serverStream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientStream)
	if err != nil || string(response) != "response" {
		t.Fatalf("response = (%q, %v), want (response, nil)", response, err)
	}
	t.Log("SMUX_NEGOTIATED_ENGINE_HALF_CLOSE_OK")
}

func TestCloseFrameTerminatesLogicalStream(t *testing.T) {
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer clientStream.Close()
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	siblingClient, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer siblingClient.Close()
	siblingServer, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer siblingServer.Close()

	if _, err := serverStream.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	if err := serverStream.Close(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "final" {
		t.Fatalf("payload = %q, want final", payload)
	}
	if _, err := clientStream.Write([]byte("response")); !errors.Is(err, io.EOF) {
		t.Fatalf("write after peer close error = %v, want %v", err, io.EOF)
	}

	if _, err := siblingClient.Write([]byte("sibling")); err != nil {
		t.Fatal(err)
	}
	siblingPayload := make([]byte, len("sibling"))
	if _, err := io.ReadFull(siblingServer, siblingPayload); err != nil {
		t.Fatal(err)
	}
	if string(siblingPayload) != "sibling" {
		t.Fatalf("sibling payload = %q, want sibling", siblingPayload)
	}
	t.Log("SMUX_FULL_CLOSE_COMPAT_OK")
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

func TestSessionFailureDeliversBufferedReceiveDataBeforeError(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	writeFrame := func(command frameCommand, streamID uint32, payload []byte) {
		t.Helper()
		encoded := make([]byte, frameHeaderSize+len(payload))
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
		copy(encoded[frameHeaderSize:], payload)
		if _, writeErr := peer.Write(encoded); writeErr != nil {
			t.Fatalf("write %v frame: %v", command, writeErr)
		}
	}

	writeFrame(frameOpen, 1, nil)
	stream, err := session.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(frameData, 1, []byte("stale"))
	// A completed following frame is the carrier barrier proving DATA has been
	// enqueued before failure; no timer or private accounting establishes it.
	writeFrame(frameKeepalive, 0, nil)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session did not observe carrier failure")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	destination := bytes.Repeat([]byte{0xcc}, len("stale"))
	count, err := stream.Read(destination)
	if count != len("stale") || err != nil || string(destination) != "stale" {
		t.Fatalf("first Read after session failure = (%d, %v, %q), want buffered payload", count, err, destination)
	}
	if count, err = stream.Read(destination); count != 0 || err == nil {
		t.Fatalf("second Read after session failure = (%d, %v), want carrier error", count, err)
	}
	session.receiveMu.Lock()
	receiveUsed := session.receiveUsed
	session.receiveMu.Unlock()
	if receiveUsed != 0 {
		t.Fatalf("receive credit after session failure = %d, want 0", receiveUsed)
	}
}

func TestSessionFailureDeliversBufferedMultiBufferBeforeError(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	writeFrame := func(command frameCommand, streamID uint32, payload []byte) {
		t.Helper()
		encoded := make([]byte, frameHeaderSize+len(payload))
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
		copy(encoded[frameHeaderSize:], payload)
		if _, writeErr := peer.Write(encoded); writeErr != nil {
			t.Fatalf("write %v frame: %v", command, writeErr)
		}
	}

	writeFrame(frameOpen, 1, nil)
	stream, err := session.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(frameData, 1, []byte("retained"))
	writeFrame(frameKeepalive, 0, nil)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session did not observe carrier failure")
	}

	multiBuffer, err := stream.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, multiBuffer.Len())
	multiBuffer.Copy(payload)
	buf.ReleaseMulti(multiBuffer)
	if string(payload) != "retained" {
		t.Fatalf("ReadMultiBuffer payload = %q, want retained", payload)
	}
	if next, readErr := stream.ReadMultiBuffer(); next != nil || readErr == nil {
		t.Fatalf("second ReadMultiBuffer = (%v, %v), want (nil, carrier error)", next, readErr)
	}
}

func TestAcceptedStreamCloseRacingSessionFailureDrainsOnce(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	writeFrame := func(command frameCommand, streamID uint32, payload []byte) {
		t.Helper()
		encoded := make([]byte, frameHeaderSize+len(payload))
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
		copy(encoded[frameHeaderSize:], payload)
		if _, writeErr := peer.Write(encoded); writeErr != nil {
			t.Fatalf("write %v frame: %v", command, writeErr)
		}
	}

	writeFrame(frameOpen, 1, nil)
	stream, err := session.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(frameData, 1, []byte("discarded"))
	writeFrame(frameKeepalive, 0, nil)

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- stream.Close()
	}()
	go func() {
		<-start
		results <- session.Close()
	}()
	close(start)
	for range 2 {
		select {
		case <-results:
		case <-time.After(time.Second):
			t.Fatal("concurrent stream/session close did not finish")
		}
	}
	if err := stream.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("second stream Close error = %v, want %v", err, io.ErrClosedPipe)
	}

	session.receiveMu.Lock()
	receiveUsed := session.receiveUsed
	session.receiveMu.Unlock()
	stream.stateMu.Lock()
	chunks, buffered := len(stream.chunks), stream.buffered
	stream.stateMu.Unlock()
	if receiveUsed != 0 || chunks != 0 || buffered != 0 {
		t.Fatalf("ownership after Close/fail race: credit=%d chunks=%d buffered=%d, want 0/0/0", receiveUsed, chunks, buffered)
	}
}

func TestAcceptStreamRacingFailureDoesNotClaimBacklog(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	stream := newStream(session, 1)
	session.streamsMu.Lock()
	session.streams[stream.id] = stream
	session.accepts <- stream
	acceptResult := make(chan error, 1)
	go func() {
		accepted, acceptErr := session.AcceptStream()
		if accepted != nil {
			acceptResult <- errors.New("AcceptStream exposed backlog after failure")
			return
		}
		acceptResult <- acceptErr
	}()

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(session.accepts) != 0 {
		select {
		case <-deadline.C:
			session.streamsMu.Unlock()
			t.Fatal("AcceptStream did not remove the backlog entry")
		default:
			runtime.Gosched()
		}
	}
	failureDone := make(chan struct{})
	go func() {
		session.fail(io.EOF)
		close(failureDone)
	}()
	select {
	case <-session.done:
	case <-deadline.C:
		session.streamsMu.Unlock()
		t.Fatal("failure did not close the session")
	}
	session.streamsMu.Unlock()

	select {
	case acceptErr := <-acceptResult:
		if !errors.Is(acceptErr, io.EOF) {
			t.Fatalf("AcceptStream error = %v, want %v", acceptErr, io.EOF)
		}
	case <-deadline.C:
		t.Fatal("AcceptStream remained blocked after failure")
	}
	select {
	case <-failureDone:
	case <-deadline.C:
		t.Fatal("failure cleanup remained blocked")
	}
}

func TestSessionFailureDrainsUnacceptedRemoteStream(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	writeFrame := func(command frameCommand, streamID uint32, payload []byte) {
		t.Helper()
		encoded := make([]byte, frameHeaderSize+len(payload))
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
		copy(encoded[frameHeaderSize:], payload)
		if _, writeErr := peer.Write(encoded); writeErr != nil {
			t.Fatalf("write %v frame: %v", command, writeErr)
		}
	}

	writeFrame(frameOpen, 1, nil)
	writeFrame(frameData, 1, []byte("private"))
	// Completing a following control frame proves that DATA was enqueued
	// without relying on scheduler timing.
	writeFrame(frameKeepalive, 0, nil)

	session.streamsMu.Lock()
	privateStream := session.streams[1]
	streamCountBeforeFailure := len(session.streams)
	session.streamsMu.Unlock()
	if privateStream == nil || streamCountBeforeFailure != 1 || len(session.accepts) != 1 {
		t.Fatalf("precondition: stream=%p map=%d backlog=%d, want non-nil/1/1", privateStream, streamCountBeforeFailure, len(session.accepts))
	}

	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session did not observe carrier failure")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	if stream, acceptErr := session.AcceptStream(); stream != nil || acceptErr == nil {
		t.Errorf("AcceptStream after failure = (%v, %v), want (nil, carrier error)", stream, acceptErr)
	}
	session.streamsMu.Lock()
	streamCount := len(session.streams)
	session.streamsMu.Unlock()
	if streamCount != 0 {
		t.Errorf("private streams retained in map = %d, want 0", streamCount)
	}
	if backlog := len(session.accepts); backlog != 0 {
		t.Errorf("private streams retained in accept backlog = %d, want 0", backlog)
	}
	session.receiveMu.Lock()
	receiveUsed := session.receiveUsed
	session.receiveMu.Unlock()
	if receiveUsed != 0 {
		t.Errorf("receive credit retained by private stream = %d, want 0", receiveUsed)
	}
	privateStream.stateMu.Lock()
	chunks, buffered, stopped := len(privateStream.chunks), privateStream.buffered, privateStream.sessionClosed
	privateStream.stateMu.Unlock()
	if chunks != 0 || buffered != 0 || !stopped {
		t.Errorf("private stream after failure: chunks=%d buffered=%d stopped=%v, want 0/0/true", chunks, buffered, stopped)
	}
}

func TestSessionFailureReleasesUnacceptedBufferedStream(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Server(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	writeFrame := func(command frameCommand, streamID uint32, payload []byte) {
		t.Helper()
		encoded := make([]byte, frameHeaderSize+len(payload))
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), command, streamID, len(payload))
		copy(encoded[frameHeaderSize:], payload)
		if _, writeErr := peer.Write(encoded); writeErr != nil {
			t.Fatalf("write %v frame: %v", command, writeErr)
		}
	}

	writeFrame(frameOpen, 1, nil)
	writeFrame(frameData, 1, []byte("unaccepted"))
	writeFrame(frameKeepalive, 0, nil)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("session did not observe carrier failure")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	session.receiveMu.Lock()
	receiveUsed := session.receiveUsed
	session.receiveMu.Unlock()
	if receiveUsed != 0 {
		t.Fatalf("unaccepted receive credit after session failure = %d, want 0", receiveUsed)
	}
}

func TestOpenStreamFailureReleasesBufferedCandidate(t *testing.T) {
	local, peer := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Client(local, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = session.Close()
	})

	openDone := make(chan error, 1)
	go func() {
		_, openErr := session.OpenStream()
		openDone <- openErr
	}()

	const streamID uint32 = 3
	var stream *Stream
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stream = session.lookupStream(streamID)
		if stream != nil {
			break
		}
	}
	if stream == nil {
		t.Fatal("OpenStream did not publish candidate")
	}
	payload := []byte("orphan")
	encoded := make([]byte, frameHeaderSize+len(payload))
	encodeFrameHeader((*[frameHeaderSize]byte)(encoded[:frameHeaderSize]), frameData, streamID, len(payload))
	copy(encoded[frameHeaderSize:], payload)
	if _, err := peer.Write(encoded); err != nil {
		t.Fatal(err)
	}
	var barrier [frameHeaderSize]byte
	encodeFrameHeader(&barrier, frameKeepalive, 0, 0)
	if _, err := peer.Write(barrier[:]); err != nil {
		t.Fatal(err)
	}
	stream.stateMu.Lock()
	buffered := stream.buffered
	stream.stateMu.Unlock()
	if buffered != len(payload) {
		t.Fatalf("candidate buffered bytes = %d, want %d", buffered, len(payload))
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-openDone; err == nil {
		t.Fatal("OpenStream unexpectedly succeeded")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	session.receiveMu.Lock()
	receiveUsed := session.receiveUsed
	session.receiveMu.Unlock()
	if receiveUsed != 0 {
		t.Fatalf("failed OpenStream receive credit = %d, want 0", receiveUsed)
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
		"stream stall timeout": func(config *Config) { config.StreamStallTimeout = 0 },
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
	first.xray.Extend(1024)
	second.xray.Extend(1024)
	if !server.reserveReceive(first.Len()) || !stream.enqueue(first) {
		t.Fatal("first frame was not queued")
	}
	if !server.reserveReceive(second.Len()) {
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

func TestSlowStreamDoesNotBlockCarrierCloseAndOtherStreams(t *testing.T) {
	client, server := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = 1024
		config.MaxStreamBuffer = 1024
		config.MaxReceiveBuffer = 4 * 1024
		config.StreamStallTimeout = 20 * time.Millisecond
	})

	slowClient, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	slowServer, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	if _, err := slowClient.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := slowClient.Write(payload); err != nil {
		t.Fatal(err)
	}

	if err := slowClient.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := slowClient.Close(); err != nil {
		t.Fatalf("close behind a full stream = %v", err)
	}
	server.receiveMu.Lock()
	receiveUsed := server.receiveUsed
	server.receiveMu.Unlock()
	if receiveUsed != 0 {
		t.Fatalf("receive reservation after stalled-stream abort = %d, want 0", receiveUsed)
	}
	if streams := server.NumStreams(); streams != 0 {
		t.Fatalf("server streams after stalled-stream abort = %d, want 0", streams)
	}

	healthyClient, err := client.OpenStream()
	if err != nil {
		t.Fatalf("open healthy stream after overflow: %v", err)
	}
	healthyServer, err := server.AcceptStream()
	if err != nil {
		t.Fatalf("accept healthy stream after overflow: %v", err)
	}
	defer healthyClient.Close()
	defer healthyServer.Close()

	if _, err := healthyClient.Write([]byte("healthy")); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("healthy"))
	if _, err := io.ReadFull(healthyServer, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != "healthy" {
		t.Fatalf("healthy payload = %q, want healthy", received)
	}

	if _, err := slowServer.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("overflowed server stream read error = %v, want %v", err, io.ErrClosedPipe)
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

type immediateWriteConn struct {
	writeErr error
}

func (*immediateWriteConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *immediateWriteConn) Write(payload []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(payload), nil
}

func (*immediateWriteConn) Close() error {
	return nil
}

func newSubmitTestSession(connection io.ReadWriteCloser, queueSize int) *Session {
	return &Session{
		conn:           connection,
		streams:        make(map[uint32]*Stream),
		accepts:        make(chan *Stream, 1),
		writeQueue:     make(chan outboundFrame, queueSize),
		done:           make(chan struct{}),
		receiveChanged: make(chan struct{}, 1),
		acceptChanged:  make(chan struct{}),
	}
}

func TestTransferredSuccessfulWriteReturnsActualResultAfterSessionFailure(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)

	session := newSubmitTestSession(&immediateWriteConn{}, 1)
	result := make(chan error, 1)
	submitDone := make(chan error, 1)
	go func() {
		submitDone <- session.submitResult(frameOpen, 3, nil, time.Time{}, result)
	}()

	var request outboundFrame
	select {
	case request = <-session.writeQueue:
	case <-time.After(time.Second):
		t.Fatal("frame was not transferred to the write queue")
	}
	writeErr := session.writeFrame(request.encoded)
	releaseFrameBuffer(request.encoded)
	if writeErr != nil {
		t.Fatalf("carrier Write error = %v, want nil", writeErr)
	}

	session.fail(io.EOF)
	// With one runnable submitter and one P, this yields after done is closed
	// while the successful carrier result is still unpublished.
	runtime.Gosched()
	request.result <- writeErr

	select {
	case err := <-submitDone:
		if err != nil {
			t.Fatalf("submitWithStateResult error = %v, want nil from successful transferred write", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transferred successful write did not complete")
	}
}

func TestTransferredFailedWriteReturnsCarrierError(t *testing.T) {
	writeFailure := errors.New("carrier write failed")
	session := newSubmitTestSession(&immediateWriteConn{writeErr: writeFailure}, 1)
	result := make(chan error, 1)
	submitDone := make(chan error, 1)
	go func() {
		submitDone <- session.submitResult(frameOpen, 3, nil, time.Time{}, result)
	}()

	var request outboundFrame
	select {
	case request = <-session.writeQueue:
	case <-time.After(time.Second):
		t.Fatal("frame was not transferred to the write queue")
	}
	writeErr := session.writeFrame(request.encoded)
	releaseFrameBuffer(request.encoded)
	request.result <- writeErr
	session.fail(writeErr)

	select {
	case err := <-submitDone:
		if !errors.Is(err, writeFailure) {
			t.Fatalf("submitWithStateResult error = %v, want %v", err, writeFailure)
		}
	case <-time.After(time.Second):
		t.Fatal("transferred failed write did not complete")
	}
}

func TestQueuedWriteCompletesAfterActiveWriteFailure(t *testing.T) {
	writeFailure := errors.New("active carrier write failed")
	session := newSubmitTestSession(&immediateWriteConn{writeErr: writeFailure}, 2)
	activeResult := make(chan error, 1)
	activeDone := make(chan error, 1)
	go func() {
		activeDone <- session.submitResult(frameOpen, 3, nil, time.Time{}, activeResult)
	}()

	var active outboundFrame
	select {
	case active = <-session.writeQueue:
	case <-time.After(time.Second):
		t.Fatal("active frame was not transferred to the write queue")
	}

	queuedResult := make(chan error, 1)
	queuedDone := make(chan error, 1)
	go func() {
		queuedDone <- session.submitResult(frameOpen, 5, nil, time.Time{}, queuedResult)
	}()
	queueDeadline := time.NewTimer(time.Second)
	defer queueDeadline.Stop()
	for len(session.writeQueue) != 1 {
		select {
		case <-queueDeadline.C:
			t.Fatal("second frame was not left queued behind the active write")
		default:
			runtime.Gosched()
		}
	}

	writeErr := session.writeFrame(active.encoded)
	releaseFrameBuffer(active.encoded)
	active.result <- writeErr
	session.fail(writeErr)

	for name, completed := range map[string]<-chan error{
		"active": activeDone,
		"queued": queuedDone,
	} {
		select {
		case err := <-completed:
			if !errors.Is(err, writeFailure) {
				t.Errorf("%s submit error = %v, want %v", name, err, writeFailure)
			}
		case <-time.After(time.Second):
			t.Errorf("%s submit did not complete", name)
		}
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- session.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Session.Close deadlocked after active and queued write completion")
	}
}

func TestSessionCloseCompletesWhenSubmitParksOnFullWriteQueue(t *testing.T) {
	carrier := newBlockingWriteConn()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := Client(carrier, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = carrier.Close()
		_ = session.Close()
	})

	if _, err := session.OpenStream(); err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- session.submitResult(frameOpen, 5, nil, time.Time{}, make(chan error, 1))
	}()
	select {
	case <-carrier.blocked:
	case <-time.After(time.Second):
		t.Fatal("carrier write did not park")
	}

	for range cap(session.writeQueue) {
		encoded := acquireFrameBuffer(frameHeaderSize)
		encodeFrameHeader((*[frameHeaderSize]byte)(encoded), frameOpen, 7, 0)
		session.writeQueue <- outboundFrame{encoded: encoded, result: make(chan error, 1)}
	}

	submitStarted := make(chan struct{})
	submitResult := make(chan error, 1)
	go func() {
		result := make(chan error, 1)
		submitResult <- session.submitWithStateResult(frameOpen, 9, nil, func() (time.Time, <-chan struct{}, error) {
			select {
			case <-submitStarted:
			default:
				close(submitStarted)
			}
			return time.Time{}, nil, nil
		}, result)
	}()
	<-submitStarted
	parkDeadline := time.Now().Add(time.Second)
	for session.submitMu.TryLock() {
		session.submitMu.Unlock()
		if time.Now().After(parkDeadline) {
			t.Fatal("submit did not park on the full write queue")
		}
		runtime.Gosched()
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- session.Close() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = carrier.Close()
		t.Fatal("Session.Close did not complete while submit was parked on a full write queue")
	}
	select {
	case err := <-submitResult:
		if err == nil {
			t.Fatal("parked submit succeeded after session close")
		}
	case <-time.After(time.Second):
		t.Fatal("parked submit did not return after session close")
	}
	if err := <-firstResult; err == nil {
		t.Fatal("active carrier write succeeded after session close")
	}
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

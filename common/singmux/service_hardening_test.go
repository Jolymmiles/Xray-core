package singmux

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

func TestServiceCarrierHandshakeDeadline(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	service.carrierHandshakeTimeout = 20 * time.Millisecond
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	started := time.Now()
	err := service.NewConnection(context.Background(), serverConn)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("NewConnection error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("carrier handshake timeout took %s", elapsed)
	}
}

func TestServiceCarrierHandshakeStopsOnContextCancellation(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverConn) }()
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		_ = clientConn.Close()
		<-result
		t.Fatal("carrier handshake remained blocked after context cancellation")
	}
}

type blockingServiceDispatcher struct {
	*echoDispatcher
	started  chan struct{}
	finished chan struct{}
	release  chan struct{}
}

func (d *blockingServiceDispatcher) DispatchLink(ctx context.Context, _ X.Destination, _ *transport.Link) error {
	d.started <- struct{}{}
	defer func() { d.finished <- struct{}{} }()
	select {
	case <-d.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestServiceReleasesAdmissionSlotAfterHandshake(t *testing.T) {
	dispatcher := &blockingServiceDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}, 3),
		finished:       make(chan struct{}, 3),
		release:        make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseHandlers := func() { releaseOnce.Do(func() { close(dispatcher.release) }) }
	defer releaseHandlers()
	service := NewService(dispatcher)
	service.maxPendingHandshakes = 2
	service.streamHandshakeTimeout = time.Second
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.NewConnection(ctx, serverConn) }()
	if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := localsmux.Client(clientConn, config)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)

	openHandledStream := func() *localsmux.Stream {
		stream, err := session.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if err := writeStreamRequest(stream, 0, destination); err != nil {
			t.Fatal(err)
		}
		if err := stream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := readStreamResponse(stream); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dispatcher.started:
		case <-time.After(time.Second):
			t.Fatal("stream handler did not enter the dispatcher")
		}
		return stream
	}

	first := openHandledStream()
	defer first.Close()
	second := openHandledStream()
	defer second.Close()
	third := openHandledStream()
	defer third.Close()

	releaseHandlers()
	for range 3 {
		select {
		case <-dispatcher.finished:
		case <-time.After(time.Second):
			t.Fatal("stream handler did not finish after dispatcher release")
		}
	}
}

func TestServiceRejectsExcessPendingHandshakeWithoutWaitingForTimeout(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	service.maxPendingHandshakes = 2
	service.streamHandshakeTimeout = time.Second

	startCarrier := func() (*localsmux.Session, context.CancelFunc) {
		clientConn, serverConn := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = service.NewConnection(ctx, serverConn) }()
		if err := writeCarrierRequest(clientConn, protocolSMUX, nil); err != nil {
			cancel()
			t.Fatal(err)
		}
		config := localsmux.DefaultConfig()
		config.KeepAliveDisabled = true
		session, err := localsmux.Client(clientConn, config)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		return session, cancel
	}

	firstCarrier, cancelFirst := startCarrier()
	defer cancelFirst()
	defer firstCarrier.Close()
	first, err := firstCarrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := firstCarrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	third, err := firstCarrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if err := third.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("first carrier did not consume both pending-handshake slots")
	}

	secondCarrier, cancelSecond := startCarrier()
	defer cancelSecond()
	defer secondCarrier.Close()
	crossCarrier, err := secondCarrier.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer crossCarrier.Close()
	if err := crossCarrier.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = crossCarrier.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("second carrier bypassed the service-wide pending-handshake limit")
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("excess handshake waited for its deadline instead of failing fast: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 50*time.Millisecond {
		t.Fatalf("excess handshake rejection took %s", elapsed)
	}
}

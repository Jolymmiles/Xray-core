package singmux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
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

func TestServiceBoundsPendingStreamHandshakes(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	service.maxConcurrentStreams = 2
	service.streamHandshakeTimeout = time.Second
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- service.NewConnection(ctx, serverConn) }()
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
	first, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	third, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	if err := writeStreamRequest(third, 0, destination); err != nil {
		t.Fatal(err)
	}
	if err := third.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(third); err == nil {
		t.Fatal("third stream was handled before a handshake slot became available")
	}
	if err := third.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := third.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(third); err != nil {
		t.Fatalf("third stream did not resume after slot release: %v", err)
	}
}

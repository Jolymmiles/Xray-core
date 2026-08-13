// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/net/http2"
)

type deadlineResponseWriter struct {
	header           http.Header
	mu               sync.Mutex
	writeDeadline    time.Time
	flushHadDeadline bool
}

func (w *deadlineResponseWriter) Header() http.Header { return w.header }
func (*deadlineResponseWriter) WriteHeader(int)       {}
func (*deadlineResponseWriter) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (w *deadlineResponseWriter) FlushError() error {
	w.mu.Lock()
	w.flushHadDeadline = !w.writeDeadline.IsZero()
	w.mu.Unlock()
	return nil
}
func (*deadlineResponseWriter) SetReadDeadline(time.Time) error { return nil }
func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.mu.Lock()
	w.writeDeadline = deadline
	w.mu.Unlock()
	return nil
}

func TestServiceAcceptsH2MuxTCPStream(t *testing.T) {
	for _, test := range []struct {
		name   string
		header []byte
	}{
		{name: "plain", header: []byte{0, 2}},
		{name: "version one without padding", header: []byte{1, 2, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
			client, closeCarrier := startH2MuxService(t, NewService(dispatcher), test.header)
			defer closeCarrier()

			destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
			response, bodyWriter := openH2MuxStream(t, client)
			defer response.Body.Close()
			if err := writeStreamRequest(bodyWriter, 0, destination); err != nil {
				t.Fatal(err)
			}
			if _, err := bodyWriter.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if err := bodyWriter.Close(); err != nil {
				t.Fatal(err)
			}

			if response.StatusCode != http.StatusOK {
				t.Fatalf("HTTP status = %d, want 200", response.StatusCode)
			}
			if err := readStreamResponse(response.Body); err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != "hello" {
				t.Fatalf("response = %q, want hello", payload)
			}
			select {
			case target := <-dispatcher.target:
				if target != destination {
					t.Fatalf("target = %s, want %s", target, destination)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not dispatch H2MUX stream")
			}
		})
	}
}

func TestServiceAcceptsH2MuxUDPStream(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	client, closeCarrier := startH2MuxService(t, NewService(dispatcher), []byte{0, 2})
	defer closeCarrier()

	defaultDestination := X.UDPDestination(X.DomainAddress("default.example"), 53)
	packetDestination := X.UDPDestination(X.DomainAddress("packet.example"), 5353)
	response, bodyWriter := openH2MuxStream(t, client)
	defer response.Body.Close()
	if err := writeStreamRequest(bodyWriter, streamFlagUDP|streamFlagPacketAddr, defaultDestination); err != nil {
		t.Fatal(err)
	}
	if err := writePacket(bodyWriter, packetDestination, []byte("query")); err != nil {
		t.Fatal(err)
	}
	if err := bodyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(response.Body); err != nil {
		t.Fatal(err)
	}
	gotDestination, payload, err := readPacket(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if gotDestination != packetDestination || string(payload) != "query" {
		t.Fatalf("packet = %s %q, want %s query", gotDestination, payload, packetDestination)
	}
}

func TestServiceBoundsH2MuxPendingHandshakes(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	service.maxPendingHandshakes = 1
	client, closeCarrier := startH2MuxService(t, service, []byte{0, 2})
	defer closeCarrier()

	firstResponse, firstWriter := openH2MuxStream(t, client)
	defer firstResponse.Body.Close()
	defer firstWriter.Close()
	if firstResponse.StatusCode != http.StatusOK {
		t.Fatalf("first HTTP status = %d, want 200", firstResponse.StatusCode)
	}

	secondResponse, secondWriter := openH2MuxStream(t, client)
	defer secondResponse.Body.Close()
	defer secondWriter.Close()
	if secondResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second HTTP status = %d, want 503", secondResponse.StatusCode)
	}
}

type lateH2OwnershipProbe struct {
	dispatches int
	leases     int
	owners     int
}

func (p *lateH2OwnershipProbe) ServeHTTP(http.ResponseWriter, *http.Request) {
	p.dispatches++
	p.leases++
	p.owners++
}

func TestServiceH2MuxWrapperRejectsLateHandlerBeforeOwnership(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	owner := &serviceCarrier{Conn: server, ctx: ctx, cancel: cancel}
	owner.handlerCond = sync.NewCond(&owner.handlerMu)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}

	probe := new(lateH2OwnershipProbe)
	handler := owner.wrapH2MuxHandler(probe)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodConnect, "https://example.com", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("late H2 handler status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if probe.dispatches != 0 || probe.leases != 0 || probe.owners != 0 {
		t.Fatalf("late H2 handler ownership = dispatches %d, leases %d, owners %d; want all zero",
			probe.dispatches, probe.leases, probe.owners)
	}
	owner.handlerMu.Lock()
	handlers := owner.handlers
	owner.handlerMu.Unlock()
	if handlers != 0 {
		t.Fatalf("late H2 handler registrations = %d, want 0", handlers)
	}
}

func TestServiceCloseCancelsH2MUXHandlerAndWaitsForServeConn(t *testing.T) {
	dispatcher := &lifecycleBlockingDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}),
		canceled:       make(chan struct{}),
		finished:       make(chan struct{}),
		release:        make(chan struct{}),
	}
	service := NewService(dispatcher)
	client, closeCarrier := startH2MuxService(t, service, []byte{0, 2})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(dispatcher.release) }) }
	t.Cleanup(func() {
		release()
		closeCarrier()
	})

	response, bodyWriter := openH2MuxStream(t, client)
	t.Cleanup(func() {
		_ = bodyWriter.Close()
		_ = response.Body.Close()
	})
	if err := writeStreamRequest(bodyWriter, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(response.Body); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, dispatcher.started, "H2MUX handler did not enter the dispatcher")

	closeResult := make(chan error, 1)
	go func() { closeResult <- service.Close() }()
	waitSignal(t, dispatcher.canceled, "Service.Close did not cancel the H2MUX handler context")
	select {
	case err := <-closeResult:
		t.Fatalf("Service.Close returned before the H2MUX handler completed: %v", err)
	default:
	}

	release()
	waitSignal(t, dispatcher.finished, "H2MUX handler did not finish")
	if err := waitResult(t, closeResult, "Service.Close did not wait for H2MUX ServeConn completion"); err != nil {
		t.Fatalf("Service.Close error = %v", err)
	}
}

func TestServiceH2MuxCarrierCloseCancelsHandler(t *testing.T) {
	dispatcher := &blockingServiceDispatcher{
		echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)},
		started:        make(chan struct{}, 1),
		finished:       make(chan struct{}, 1),
		release:        make(chan struct{}),
	}
	client, closeCarrier := startH2MuxService(t, NewService(dispatcher), []byte{0, 2})
	response, bodyWriter := openH2MuxStream(t, client)
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	if err := writeStreamRequest(bodyWriter, 0, destination); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(response.Body); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.started:
	case <-time.After(time.Second):
		t.Fatal("H2MUX handler did not enter dispatcher")
	}

	closeCarrier()
	_ = bodyWriter.Close()
	_ = response.Body.Close()
	select {
	case <-dispatcher.finished:
	case <-time.After(time.Second):
		t.Fatal("H2MUX handler was not canceled by carrier close")
	}
}

func TestServiceH2MuxBoundsInitialResponseFlush(t *testing.T) {
	var requestBody bytes.Buffer
	if err := writeStreamRequest(&requestBody, 0, X.TCPDestination(X.DomainAddress("example.com"), 443)); err != nil {
		t.Fatal(err)
	}
	writer := &deadlineResponseWriter{header: make(http.Header)}
	request := (&http.Request{
		Method: http.MethodConnect,
		Body:   io.NopCloser(&requestBody),
	}).WithContext(context.Background())
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	service := NewService(&handshakeBenchmarkDispatcher{echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)}})
	service.handleH2MuxStream(writer, request, server, newServerBrutalController(request.Context(), service.setBrutalOptions), session.PresenceScope{})

	writer.mu.Lock()
	flushHadDeadline := writer.flushHadDeadline
	deadlineAfterHandshake := writer.writeDeadline
	writer.mu.Unlock()
	if !flushHadDeadline {
		t.Fatal("initial HTTP 200 flush had no write deadline")
	}
	if !deadlineAfterHandshake.IsZero() {
		t.Fatalf("write deadline remained set after handshake: %v", deadlineAfterHandshake)
	}
}

func TestServiceH2MuxBrutalSharesOneNegotiationPerCarrier(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	applied := make(chan uint64, 2)
	service.setBrutalOptions = func(_ net.Conn, rate uint64) error {
		applied <- rate
		return nil
	}
	client, closeCarrier := startH2MuxServiceWithContext(t, service, []byte{0, 2}, func(serverConnection net.Conn) context.Context {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: serverConnection})
		return ContextWithServerBrutalOptions(ctx, BrutalOptions{
			Enabled: true, SendBPS: 70_000_000, ReceiveBPS: 60_000_000,
		})
	})
	defer closeCarrier()

	exchange := func() error {
		response, bodyWriter := openH2MuxStream(t, client)
		defer response.Body.Close()
		defer bodyWriter.Close()
		if err := writeStreamRequest(bodyWriter, 0, X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 0)); err != nil {
			t.Fatal(err)
		}
		if err := writeBrutalRequest(bodyWriter, 80_000_000); err != nil {
			t.Fatal(err)
		}
		if err := readStreamResponse(response.Body); err != nil {
			t.Fatal(err)
		}
		_, err := readBrutalResponse(response.Body)
		return err
	}
	if err := exchange(); err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}
	if err := exchange(); err == nil {
		t.Fatal("duplicate exchange succeeded")
	}
	if got := <-applied; got != 70_000_000 {
		t.Fatalf("applied rate = %d, want 70000000", got)
	}
	select {
	case got := <-applied:
		t.Fatalf("duplicate exchange reapplied rate %d", got)
	default:
	}
	select {
	case target := <-dispatcher.target:
		t.Fatalf("H2MUX control stream reached router: %s", target)
	default:
	}
}

func startH2MuxService(t *testing.T, service *Service, carrierHeader []byte) (*http2.ClientConn, func()) {
	t.Helper()
	return startH2MuxServiceWithContext(t, service, carrierHeader, func(net.Conn) context.Context {
		return context.Background()
	})
}

func startH2MuxServiceWithContext(t *testing.T, service *Service, carrierHeader []byte, carrierContext func(net.Conn) context.Context) (*http2.ClientConn, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(carrierContext(serverConnection))
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverConnection) }()
	if _, err := clientConnection.Write(carrierHeader); err != nil {
		cancel()
		_ = clientConnection.Close()
		t.Fatal(err)
	}
	client, err := (&http2.Transport{}).NewClientConn(clientConnection)
	if err != nil {
		cancel()
		_ = clientConnection.Close()
		t.Fatal(err)
	}
	return client, func() {
		_ = client.Close()
		cancel()
		_ = clientConnection.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("H2MUX service did not stop after carrier close")
		}
	}
}

func openH2MuxStream(t *testing.T, client *http2.ClientConn) (*http.Response, *io.PipeWriter) {
	t.Helper()
	bodyReader, bodyWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: "localhost"},
		Host:   "localhost",
		Header: make(http.Header),
		Body:   bodyReader,
	}
	responseResult := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := client.RoundTrip(request)
		responseResult <- struct {
			response *http.Response
			err      error
		}{response, err}
	}()
	select {
	case result := <-responseResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.response, bodyWriter
	case <-time.After(time.Second):
		_ = bodyWriter.Close()
		t.Fatal("H2MUX CONNECT did not receive response headers")
		return nil, nil
	}
}

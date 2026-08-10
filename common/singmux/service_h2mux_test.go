// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
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
	service.handleH2MuxStream(writer, request, server)

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

func startH2MuxService(t *testing.T, service *Service, carrierHeader []byte) (*http2.ClientConn, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
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

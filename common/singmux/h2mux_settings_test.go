// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"golang.org/x/net/http2"
)

// defaultH2MuxReadFrameSize mirrors golang.org/x/net/http2 defaultMaxReadFrameSize,
// which applies whenever http2.Server.MaxReadFrameSize is left unset.
const defaultH2MuxReadFrameSize uint32 = 1 << 20

func TestH2MuxCarrierAdvertisesMaxFrameSize(t *testing.T) {
	for _, test := range []struct {
		name    string
		options *H2MuxOptions
		want    uint32
	}{
		{name: "omitted", want: defaultH2MuxReadFrameSize},
		{name: "zero", options: &H2MuxOptions{}, want: defaultH2MuxReadFrameSize},
		{name: "protocol minimum", options: &H2MuxOptions{MaxReadFrameSize: 16384}, want: 16384},
		{name: "protocol maximum", options: &H2MuxOptions{MaxReadFrameSize: H2MuxMaxReadFrameSize}, want: H2MuxMaxReadFrameSize},
		{name: "below protocol minimum", options: &H2MuxOptions{MaxReadFrameSize: 16383}, want: defaultH2MuxReadFrameSize},
		{name: "above protocol maximum", options: &H2MuxOptions{MaxReadFrameSize: H2MuxMaxReadFrameSize + 1}, want: defaultH2MuxReadFrameSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
			defer service.Close()
			ctx := context.Background()
			if test.options != nil {
				ctx = ContextWithServerH2MuxOptions(ctx, *test.options)
			}
			if got := h2muxAdvertisedMaxFrameSize(t, service, ctx); got != test.want {
				t.Fatalf("advertised SETTINGS_MAX_FRAME_SIZE = %d, want %d", got, test.want)
			}
		})
	}
}

func TestH2MuxCarrierMaxFrameSizeDoesNotLeakBetweenInbounds(t *testing.T) {
	service := NewService(&echoDispatcher{target: make(chan X.Destination, 1)})
	defer service.Close()

	capped := ContextWithServerH2MuxOptions(context.Background(), H2MuxOptions{MaxReadFrameSize: 16384})
	other := ContextWithServerH2MuxOptions(context.Background(), H2MuxOptions{MaxReadFrameSize: 32768})
	for _, test := range []struct {
		name string
		ctx  context.Context
		want uint32
	}{
		{name: "capped inbound", ctx: capped, want: 16384},
		{name: "unconfigured inbound", ctx: context.Background(), want: defaultH2MuxReadFrameSize},
		{name: "other capped inbound", ctx: other, want: 32768},
		{name: "capped inbound again", ctx: capped, want: 16384},
	} {
		if got := h2muxAdvertisedMaxFrameSize(t, service, test.ctx); got != test.want {
			t.Fatalf("%s advertised SETTINGS_MAX_FRAME_SIZE = %d, want %d", test.name, got, test.want)
		}
	}
}

func TestSMuxCarrierIgnoresH2MuxOptions(t *testing.T) {
	dispatcher := &echoDispatcher{target: make(chan X.Destination, 1)}
	service := NewService(dispatcher)
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(ContextWithServerH2MuxOptions(context.Background(), H2MuxOptions{MaxReadFrameSize: 16384}))
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverConnection) }()
	t.Cleanup(func() {
		cancel()
		_ = clientConnection.Close()
		_ = service.Close()
	})

	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		t.Fatal(err)
	}
	config := mplsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	clientSession, err := mplsmux.Client(clientConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)
	if err := writeStreamRequest(stream, 0, destination); err != nil {
		t.Fatal(err)
	}
	if err := readStreamResponse(stream); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dispatcher.target:
		if got != destination {
			t.Fatalf("SMUX destination = %v, want %v", got, destination)
		}
	case <-time.After(time.Second):
		t.Fatal("SMUX stream was not dispatched")
	}

	payload := []byte("smux stays unaffected")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("SMUX echo = %q, want %q", echo, payload)
	}
}

// h2muxAdvertisedMaxFrameSize completes one H2MUX carrier handshake and returns
// the SETTINGS_MAX_FRAME_SIZE of the initial server SETTINGS frame.
func h2muxAdvertisedMaxFrameSize(t *testing.T, service *Service, ctx context.Context) uint32 {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	carrierCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(carrierCtx, serverConnection) }()
	defer func() {
		cancel()
		_ = clientConnection.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("H2MUX service did not stop after carrier close")
		}
	}()

	_ = clientConnection.SetDeadline(time.Now().Add(5 * time.Second))
	framer := http2.NewFramer(clientConnection, clientConnection)
	handshake := make(chan error, 1)
	go func() {
		if err := writeCarrierRequest(clientConnection, protocolH2MUX, nil); err != nil {
			handshake <- err
			return
		}
		if _, err := io.WriteString(clientConnection, http2.ClientPreface); err != nil {
			handshake <- err
			return
		}
		handshake <- framer.WriteSettings()
	}()

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok || settings.IsAck() {
			continue
		}
		value, ok := settings.Value(http2.SettingMaxFrameSize)
		if !ok {
			t.Fatal("server SETTINGS frame carries no SETTINGS_MAX_FRAME_SIZE")
		}
		if err := <-handshake; err != nil {
			t.Fatal(err)
		}
		return value
	}
}

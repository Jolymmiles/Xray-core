package splithttp

import (
	"bufio"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// The XHTTP client's HTTP/2 preface is visible to whoever terminates its TLS,
// such as a CDN. Release builds pass -tags http2legacy, which keeps x/net's
// own HTTP/2 client; without the tag x/net wraps net/http and the first
// SETTINGS frame advertises MAX_FRAME_SIZE 1048576 instead of 16384. A change
// here changes the client's fingerprint and needs a camouflage assessment
// (docs/FORK.md).
func TestHTTP2ClientPrefaceMatchesReleaseBuild(t *testing.T) {
	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	key, err := x509.ParsePKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	prefaces := make(chan clientPreface, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			prefaces <- clientPreface{err: err}
			return
		}
		defer conn.Close()
		prefaces <- readClientPreface(gotls.Server(conn, serverConfig))
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-serverDone
	})

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{H2Flow: &H2FlowConfig{Mode: 2}}, // stock HTTP/2 wiring, whatever XRAY_XHTTP_FLOW says
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			ServerName:           "localhost",
			Fingerprint:          "chrome",
			PinnedPeerCertSha256: [][]byte{certificateHash[:]},
		},
	}
	port := listener.Addr().(*stdnet.TCPAddr).Port
	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, net.Port(port)), streamSettings).(*DefaultDialerClient)
	if client.httpVersion != "2" {
		t.Fatalf("XHTTP client chose HTTP/%s, want HTTP/2", client.httpVersion)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
		if err != nil {
			return
		}
		if response, err := client.client.Do(request); err == nil {
			_ = response.Body.Close()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-requestDone
	})

	var preface clientPreface
	select {
	case preface = <-prefaces:
	case <-ctx.Done():
		t.Fatal("XHTTP client sent no HTTP/2 preface before the deadline")
	}
	if preface.err != nil {
		t.Fatalf("read XHTTP client preface: %v", preface.err)
	}
	wantSettings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 4 << 20},
		{ID: http2.SettingMaxFrameSize, Val: 16 << 10},
		{ID: http2.SettingMaxHeaderListSize, Val: 10 << 20},
	}
	if !slices.Equal(preface.settings, wantSettings) {
		t.Errorf("XHTTP client SETTINGS %v, want %v as release builds (-tags http2legacy) send", preface.settings, wantSettings)
	}
	if want := uint32(1 << 30); preface.connectionWindowIncrement != want {
		t.Errorf("XHTTP client connection WINDOW_UPDATE increment %d, want %d", preface.connectionWindowIncrement, want)
	}
}

type clientPreface struct {
	settings                  []http2.Setting
	connectionWindowIncrement uint32
	err                       error
}

// readClientPreface completes the TLS handshake and reads the client's
// connection preface: the magic string, its SETTINGS frame and the
// connection-level WINDOW_UPDATE that follows it.
func readClientPreface(conn *gotls.Conn) clientPreface {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return clientPreface{err: err}
	}
	if err := conn.Handshake(); err != nil {
		return clientPreface{err: err}
	}
	reader := bufio.NewReader(conn)
	magic := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return clientPreface{err: err}
	}
	if string(magic) != http2.ClientPreface {
		return clientPreface{err: errors.New("bad HTTP/2 client magic")}
	}
	framer := http2.NewFramer(io.Discard, reader)
	frame, err := framer.ReadFrame()
	if err != nil {
		return clientPreface{err: err}
	}
	settingsFrame, ok := frame.(*http2.SettingsFrame)
	if !ok || settingsFrame.IsAck() {
		return clientPreface{err: errors.New("first client frame is not SETTINGS: " + frame.Header().String())}
	}
	var preface clientPreface
	_ = settingsFrame.ForeachSetting(func(setting http2.Setting) error {
		preface.settings = append(preface.settings, setting)
		return nil
	})
	frame, err = framer.ReadFrame()
	if err != nil {
		return clientPreface{err: err}
	}
	windowUpdate, ok := frame.(*http2.WindowUpdateFrame)
	if !ok || windowUpdate.StreamID != 0 {
		return clientPreface{err: errors.New("second client frame is not a connection WINDOW_UPDATE: " + frame.Header().String())}
	}
	preface.connectionWindowIncrement = windowUpdate.Increment
	return preface
}

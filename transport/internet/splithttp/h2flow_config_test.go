package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestH2FlowMode(t *testing.T) {
	defer func(v bool) { flowEnabled = v }(flowEnabled)
	for _, env := range []bool{false, true} {
		flowEnabled = env
		for mode, want := range map[int32]bool{0: env, 1: true, 2: false} {
			c := &Config{H2Flow: &H2FlowConfig{Mode: mode}}
			if got := c.h2FlowOn(); got != want {
				t.Errorf("env %v, mode %d: got %v, want %v", env, mode, got, want)
			}
		}
		if got := (&Config{}).h2FlowOn(); got != env {
			t.Errorf("env %v without h2Flow: got %v", env, got)
		}
	}
}

func TestH2ReceiveConfig(t *testing.T) {
	defer func(v bool) { flowEnabled = v }(flowEnabled)
	flowEnabled = false
	for _, tc := range []struct {
		name         string
		flow         *H2FlowConfig
		server       bool
		stream, conn int
	}{
		{"server, governor off", nil, true, 0, 0},
		{"server, governor on", &H2FlowConfig{Mode: 1}, true, flowServerReceiveWindow, flowServerReceiveWindow},
		{"server, governor on, set", &H2FlowConfig{Mode: 1, MaxStreamReceiveWindow: 2 << 20}, true, 2 << 20, flowServerReceiveWindow},
		{"server, governor off, set", &H2FlowConfig{Mode: 2, MaxConnectionReceiveWindow: 3 << 20}, true, 0, 3 << 20},
		{"client, governor on", &H2FlowConfig{Mode: 1}, false, 0, 0},
		{"client, set", &H2FlowConfig{Mode: 1, MaxStreamReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 16 << 20}, false, 8 << 20, 16 << 20},
	} {
		conf := (&Config{H2Flow: tc.flow}).h2ReceiveConfig(tc.server)
		var stream, conn int
		if conf != nil {
			stream, conn = conf.MaxReceiveBufferPerStream, conf.MaxReceiveBufferPerConnection
		}
		if stream != tc.stream || conn != tc.conn {
			t.Errorf("%s: got %d/%d, want %d/%d", tc.name, stream, conn, tc.stream, tc.conn)
		}
	}
}

// readSettings reads frames until it has seen the peer's SETTINGS and the
// connection-level WINDOW_UPDATE that follows them.
func readSettings(t *testing.T, r io.Reader) (initialWindow, connIncrement uint32) {
	t.Helper()
	header := make([]byte, 9)
	for connIncrement == 0 {
		if _, err := io.ReadFull(r, header); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatal(err)
		}
		stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		switch header[3] {
		case h2Settings:
			if header[4]&h2FlagAck != 0 {
				continue
			}
			initialWindow = h2InitWindow
			for i := 0; i+6 <= len(payload); i += 6 {
				if binary.BigEndian.Uint16(payload[i:]) == 0x4 {
					initialWindow = binary.BigEndian.Uint32(payload[i+2:])
				}
			}
		case h2WindowUpdate:
			if stream == 0 {
				connIncrement = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		}
	}
	return
}

func TestH2TransportGrantsWindows(t *testing.T) {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer ln.Close()

	h2 := newH2Transport(&http.HTTP2Config{MaxReceiveBufferPerStream: 6 << 20, MaxReceiveBufferPerConnection: 16 << 20})
	h2.DialTLSContext = func(ctx context.Context, network, _ string, _ *gotls.Config) (gonet.Conn, error) {
		var d gonet.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		if resp, err := h2.RoundTrip(req); err == nil {
			resp.Body.Close()
		}
	}()

	conn, err := ln.Accept()
	common.Must(err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	preface := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Fatal(err)
	}
	stream, connInc := readSettings(t, conn)
	if stream != 6<<20 || connInc != 16<<20 {
		t.Fatalf("client granted %d per stream and %d per connection, want %d and %d", stream, connInc, 6<<20, 16<<20)
	}
}

func TestH2ServerGrantsWindows(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flow          *H2FlowConfig
		stream, conn  uint32
		governedShown bool
	}{
		{"governor off, set", &H2FlowConfig{Mode: 2, MaxStreamReceiveWindow: 3 << 20, MaxConnectionReceiveWindow: 5 << 20}, 3 << 20, 5 << 20, false},
		{"governor off, default", &H2FlowConfig{Mode: 2}, 1 << 20, 1 << 20, false},
		// The server grants flowServerReceiveWindow on the connection; the
		// governor shows Go's default until readers take more.
		{"governor on, default", &H2FlowConfig{Mode: 1}, flowServerReceiveWindow, flowConnFloor, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := tcp.PickPort()
			listen, err := ListenXH(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
				ProtocolName:     "splithttp",
				ProtocolSettings: &Config{Path: "shs", H2Flow: tc.flow},
			}, func(conn stat.Connection) { conn.Close() })
			common.Must(err)
			defer listen.Close()

			conn, err := gonet.Dial("tcp", net.LocalHostIP.String()+":"+port.String())
			common.Must(err)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			common.Must2(conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")))
			common.Must2(conn.Write([]byte{0, 0, 0, h2Settings, 0, 0, 0, 0, 0}))

			stream, connInc := readSettings(t, conn)
			if connWindow := connInc + h2InitWindow; connWindow != tc.conn {
				t.Errorf("connection window %d, want %d", connWindow, tc.conn)
			}
			if tc.governedShown {
				// The governor shows the client a small window and hands out
				// the rest of what the server grants as it is read.
				if stream >= tc.stream {
					t.Errorf("governed stream window shown as %d, want below %d", stream, tc.stream)
				}
			} else if stream != tc.stream {
				t.Errorf("stream window %d, want %d", stream, tc.stream)
			}
		})
	}
}

// TestH2WindowsEndToEnd runs governed duplex streams between a server and a
// client that both grant larger windows than Go does, checking every byte.
func TestH2WindowsEndToEnd(t *testing.T) {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	tl := &testListener{Listener: ln, up: flowDefault, down: flowDefault}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:   http.HandlerFunc(echoHandler),
		Protocols: protocols,
		HTTP2:     (&Config{H2Flow: &H2FlowConfig{Mode: 1}}).h2ReceiveConfig(true),
	}
	go srv.Serve(tl)
	defer srv.Close()

	h2 := newH2Transport((&Config{H2Flow: &H2FlowConfig{
		Mode:                       1,
		MaxStreamReceiveWindow:     8 << 20,
		MaxConnectionReceiveWindow: 16 << 20,
	}}).h2ReceiveConfig(false))
	h2.AllowHTTP = true
	h2.DialTLSContext = func(ctx context.Context, network, _ string, _ *gotls.Config) (gonet.Conn, error) {
		c, err := (&gonet.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		if err != nil {
			return nil, err
		}
		return newFlowClientConn(c), nil
	}
	client := &http.Client{Transport: h2}

	const size = 32 << 20
	errs := make(chan error, 4)
	for i := range 4 {
		go func() {
			data := make([]byte, size)
			for j := range data {
				data[j] = byte(j*7 + i)
			}
			pr, pw := io.Pipe()
			go func() {
				pw.CloseWithError(func() error {
					_, err := pw.Write(data)
					return err
				}())
			}()
			resp, err := client.Post("https://example.com/", "application/octet-stream", pr)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err == nil && !bytes.Equal(got, data) {
				err = fmt.Errorf("stream %d: echoed %d bytes that differ from the %d sent", i, len(got), size)
			}
			errs <- err
		}()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

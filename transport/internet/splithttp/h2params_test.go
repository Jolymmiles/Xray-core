package splithttp

import (
	"context"
	"encoding/binary"
	"io"
	gonet "net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// TestServerHTTP2Config checks how the server combines upstream's h2Params
// with the fork's h2Flow: h2Params is the base, an explicit h2Flow window
// overrides it, and the governor's defaults fill only windows still unset.
func TestServerHTTP2Config(t *testing.T) {
	for _, tc := range []struct {
		name         string
		config       *Config
		nilConfig    bool
		stream, conn int
		maxStreams   uint32
		wantErr      string
	}{
		{name: "nothing set", config: &Config{H2Flow: &H2FlowConfig{Mode: 2}}, nilConfig: true},
		{
			name:   "h2Params only",
			config: &Config{H2Flow: &H2FlowConfig{Mode: 2}, H2Params: []byte(`{"MaxConcurrentStreams":7,"MaxReceiveBufferPerStream":3145728}`)},
			stream: 3 << 20, maxStreams: 7,
		},
		{
			name: "h2Flow windows override h2Params",
			config: &Config{
				H2Flow:   &H2FlowConfig{Mode: 2, MaxStreamReceiveWindow: 2 << 20},
				H2Params: []byte(`{"MaxReceiveBufferPerStream":3145728,"MaxReceiveBufferPerConnection":5242880}`),
			},
			stream: 2 << 20, conn: 5 << 20,
		},
		{
			name:   "governor defaults fill only unset windows",
			config: &Config{H2Flow: &H2FlowConfig{Mode: 1}, H2Params: []byte(`{"MaxReceiveBufferPerStream":3145728}`)},
			stream: 3 << 20, conn: flowServerReceiveWindow,
		},
		{
			name:   "governor defaults without h2Params",
			config: &Config{H2Flow: &H2FlowConfig{Mode: 1}},
			stream: flowServerReceiveWindow, conn: flowServerReceiveWindow,
		},
		{
			name:    "invalid h2Params",
			config:  &Config{H2Params: []byte(`{"MaxConcurrentStreams":`)},
			wantErr: "failed to parse h2Params",
		},
		{
			name:    "governed stream limit above what the governor tracks",
			config:  &Config{H2Flow: &H2FlowConfig{Mode: 1}, H2Params: []byte(`{"MaxConcurrentStreams":4097}`)},
			wantErr: "MaxConcurrentStreams",
		},
		{
			name:       "stock stream limit above what the governor tracks",
			config:     &Config{H2Flow: &H2FlowConfig{Mode: 2}, H2Params: []byte(`{"MaxConcurrentStreams":4097}`)},
			maxStreams: 4097,
		},
		{
			name:   "governed stream limit at what the governor tracks",
			config: &Config{H2Flow: &H2FlowConfig{Mode: 1}, H2Params: []byte(`{"MaxConcurrentStreams":4096}`)},
			stream: flowServerReceiveWindow, conn: flowServerReceiveWindow, maxStreams: 4096,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.serverHTTP2Config()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.nilConfig {
				if got != nil {
					t.Fatalf("config %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("config nil")
			}
			want := http.HTTP2Config{MaxReceiveBufferPerStream: tc.stream, MaxReceiveBufferPerConnection: tc.conn, MaxConcurrentStreams: int(tc.maxStreams)}
			if got.MaxReceiveBufferPerStream != want.MaxReceiveBufferPerStream ||
				got.MaxReceiveBufferPerConnection != want.MaxReceiveBufferPerConnection ||
				got.MaxConcurrentStreams != want.MaxConcurrentStreams {
				t.Fatalf("config %+v, want windows %d/%d and %d streams", got, tc.stream, tc.conn, tc.maxStreams)
			}
		})
	}
}

// TestListenXHInvalidH2ParamsReleasesAddress checks that an h2Params the
// server cannot parse fails ListenXH without leaving the address bound.
func TestListenXHInvalidH2ParamsReleasesAddress(t *testing.T) {
	port := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "shs", H2Params: []byte(`not json`)},
	}, func(conn stat.Connection) { conn.Close() })
	if err == nil {
		listen.Close()
		t.Fatal("ListenXH accepted an invalid h2Params")
	}
	ln, err := gonet.Listen("tcp", net.LocalHostIP.String()+":"+port.String())
	if err != nil {
		t.Fatalf("address still bound after the failed ListenXH: %v", err)
	}
	ln.Close()
}

// TestH2ParamsReachServerSettings checks that h2Params set what the server
// advertises in its SETTINGS frame.
func TestH2ParamsReachServerSettings(t *testing.T) {
	port := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{Path: "shs", H2Flow: &H2FlowConfig{Mode: 2}, H2Params: []byte(
			`{"MaxConcurrentStreams":77,"MaxReceiveBufferPerStream":3145728,"MaxReceiveBufferPerConnection":5242880}`)},
	}, func(conn stat.Connection) { conn.Close() })
	common.Must(err)
	defer listen.Close()

	conn, err := gonet.Dial("tcp", net.LocalHostIP.String()+":"+port.String())
	common.Must(err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	common.Must2(conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")))
	common.Must2(conn.Write([]byte{0, 0, 0, h2Settings, 0, 0, 0, 0, 0}))

	settings, connInc := readServerSettings(t, conn)
	if got := settings[h2SettingMaxConcurrentStreams]; got != 77 {
		t.Errorf("max concurrent streams %d, want 77", got)
	}
	if got := settings[h2SettingInitialWindowSize]; got != 3<<20 {
		t.Errorf("stream window %d, want %d", got, 3<<20)
	}
	if connWindow := connInc + h2InitWindow; connWindow != 5<<20 {
		t.Errorf("connection window %d, want %d", connWindow, 5<<20)
	}
}

const h2SettingMaxConcurrentStreams = 0x3

// readServerSettings reads frames until the server's first SETTINGS and its
// connection WINDOW_UPDATE, and returns every setting the SETTINGS carried
// with the connection window increment.
func readServerSettings(t *testing.T, r io.Reader) (map[uint16]uint32, uint32) {
	t.Helper()
	var settings map[uint16]uint32
	var connIncrement uint32
	header := make([]byte, 9)
	for settings == nil || connIncrement == 0 {
		if _, err := io.ReadFull(r, header); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatal(err)
		}
		stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		switch {
		case header[3] == h2Settings && header[4]&h2FlagAck == 0 && settings == nil:
			settings = map[uint16]uint32{}
			for i := 0; i+6 <= len(payload); i += 6 {
				settings[binary.BigEndian.Uint16(payload[i:])] = binary.BigEndian.Uint32(payload[i+2:])
			}
		case header[3] == h2WindowUpdate && stream == 0:
			connIncrement = binary.BigEndian.Uint32(payload) & 0x7fffffff
		}
	}
	return settings, connIncrement
}

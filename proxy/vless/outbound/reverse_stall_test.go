package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// A running instance closes an outbound when RemoveOutbound removes it and
// when the instance shuts down.
var bridgeClosers = []struct {
	name  string
	close func(outbound.Manager) func() error
}{
	{name: "remove", close: removeBridge},
	{name: "close", close: func(ohm outbound.Manager) func() error {
		return ohm.GetHandler("bridge").Close
	}},
}

// A censor that stalls the server after the TCP handshake leaves the bridge
// waiting on its TLS handshake. Closing the outbound must not wait for it.
func TestReverseCloseAbortsStalledTLSHandshake(t *testing.T) {
	for _, closer := range bridgeClosers {
		t.Run(closer.name, func(t *testing.T) {
			server := newCarrierListener(t)
			ohm, _ := newReverseClient(t, server.destination(), reverseAccount(), &internet.StreamConfig{
				SecurityType: serial.GetMessageType(&xtls.Config{}),
				SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&xtls.Config{
					ServerName: "example.com",
				})},
			})
			// Should closing the outbound wait for the handshake, the
			// instance's own Close would too: end the handshake first.
			t.Cleanup(server.close)
			c := server.waitCarrier(t)

			closeWithin(t, closer.close(ohm), 10*time.Second)
			waitCarrierEnded(t, c)
		})
	}
}

// The VLESS encryption handshake reads its server's reply without a context
// or deadline. Closing the outbound must not wait for a server that never
// replies.
func TestReverseCloseAbortsStalledEncryptionHandshake(t *testing.T) {
	for _, closer := range bridgeClosers {
		t.Run(closer.name, func(t *testing.T) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			account := reverseAccount()
			account.Encryption = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			server := newCarrierListener(t)
			ohm, _ := newReverseClient(t, server.destination(), account, &internet.StreamConfig{})
			t.Cleanup(server.close)
			c := server.waitCarrier(t)

			closeWithin(t, closer.close(ohm), 10*time.Second)
			waitCarrierEnded(t, c)
		})
	}
}

// webSocketCarrierServer accepts WebSocket carriers, reads and discards what
// the client sends and never answers.
func newWebSocketCarrierServer(t *testing.T) (net.Destination, chan *carrier) {
	t.Helper()
	port := tcp.PickPort()
	accepted := make(chan *carrier, 16)
	listener, err := websocket.ListenWS(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &websocket.Config{Path: "rvs"},
	}, func(conn stat.Connection) {
		c := &carrier{ended: make(chan struct{})}
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			close(c.ended)
		}()
		select {
		case accepted <- c:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return net.TCPDestination(net.LocalHostIP, port), accepted
}

// With WebSocket early data the bridge's first write dials its carrier, and
// closing the outbound closes that carrier while the bridge still reads and
// writes it.
func TestReverseCloseOverWebSocketEarlyData(t *testing.T) {
	for _, closer := range bridgeClosers {
		t.Run(closer.name, func(t *testing.T) {
			server, accepted := newWebSocketCarrierServer(t)
			ohm, _ := newReverseClient(t, server, reverseAccount(), &internet.StreamConfig{
				ProtocolName: "websocket",
				TransportSettings: []*internet.TransportConfig{{
					ProtocolName: "websocket",
					Settings:     serial.ToTypedMessage(&websocket.Config{Path: "rvs", Ed: 2048}),
				}},
			})
			var c *carrier
			select {
			case c = <-accepted:
			case <-time.After(15 * time.Second):
				t.Fatal("the VLESS reverse did not connect to its server")
			}

			closeWithin(t, closer.close(ohm), 10*time.Second)
			waitCarrierEnded(t, c)
		})
	}
}

package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
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

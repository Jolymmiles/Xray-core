package tls_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"fmt"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

// handshakeUClient is how Xray's dialers start a uTLS session: with the
// outer ALPN of the WebSocket and HTTPUpgrade transports when http11 is set.
func handshakeUClient(ctx context.Context, conn stdnet.Conn, config *gotls.Config, fingerprint *utls.ClientHelloID, http11 bool) (*xraytls.UConn, error) {
	var options []xraytls.UClientOption
	if http11 {
		options = append(options, xraytls.WithHTTP11ALPN())
	}
	return xraytls.ClientHandshake(ctx, conn, config, fingerprint, options...)
}

// A fingerprint without ALPN gets the WebSocket ALPN extension added. With a
// session ticket loaded the hello also carries pre_shared_key, which RFC
// 8446, Section 4.2.11, requires to be the last extension; added after it,
// ALPN breaks the resumed handshake.
func TestUClientHTTP11ALPNWithResumedSession(t *testing.T) {
	listener, serverErrors := startTLSServer(t, 2, gotls.VersionTLS13)
	defer listener.Close()
	config := &gotls.Config{
		InsecureSkipVerify: true,
		ServerName:         fmt.Sprintf("session-%d.test", sessionResumptionTestID.Add(1)),
		ClientSessionCache: gotls.NewLRUClientSessionCache(1),
		NextProtos:         []string{"http/1.1"},
	}
	fingerprint := randomizedFingerprint(t, "randomizednoalpn", randomizedSeeds[0].seed)
	for i := range 2 {
		rawConn, err := stdnet.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))
		conn, err := handshakeUClient(context.Background(), rawConn, config, fingerprint, true)
		if err != nil {
			rawConn.Close()
			t.Fatalf("handshake %d: %v", i+1, err)
		}
		var marker [1]byte
		if _, err := io.ReadFull(conn, marker[:]); err != nil || marker[0] != byte(i) {
			conn.Close()
			t.Fatalf("marker %d: %v %v", i+1, marker, err)
		}
		resumed := conn.ConnectionState().DidResume
		if _, err := conn.Write(marker[:]); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		if resumed != (i == 1) {
			t.Fatalf("connection %d resumed = %v", i+1, resumed)
		}
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

// testECHKeys returns a one-config ECHConfigList for publicName and the
// server key that decrypts it.
func testECHKeys(t *testing.T, publicName string) (list []byte, key gotls.EncryptedClientHelloKey) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var config cryptobyte.Builder
	config.AddUint16(0xfe0d) // ECH draft version
	config.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7)     // config_id
		b.AddUint16(0x20) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(private.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(1) // HKDF-SHA256
			b.AddUint16(1) // AES-128-GCM
		})
		b.AddUint8(0) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	single := config.BytesOrPanic()
	var configs cryptobyte.Builder
	configs.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(single) })
	return configs.BytesOrPanic(), gotls.EncryptedClientHelloKey{Config: single, PrivateKey: private.Bytes()}
}

// ECH hides the real server name and ALPN in the inner hello. The WebSocket
// ALPN goes there too and leaves the outer hello's alone.
func TestUClientECH(t *testing.T) {
	list, key := testECHKeys(t, "public.example")
	generated, _ := cert.MustGenerate(nil, cert.CommonName("inner.example"), cert.DNSNames("inner.example"))
	certificate, err := gotls.X509KeyPair(generated.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	for _, http11 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http11=%v", http11), func(t *testing.T) {
			listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
				Certificates:             []gotls.Certificate{certificate},
				MinVersion:               gotls.VersionTLS13,
				NextProtos:               []string{"h2", "http/1.1"},
				EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{key},
			})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			// Runs last, after the client has closed its connection.
			defer func() {
				_ = listener.Close()
				<-done
			}()
			type serverState struct {
				state gotls.ConnectionState
				err   error
			}
			states := make(chan serverState, 1)
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					states <- serverState{err: err}
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				tlsConn := conn.(*gotls.Conn)
				err = tlsConn.Handshake()
				states <- serverState{state: tlsConn.ConnectionState(), err: err}
				_, _ = io.Copy(io.Discard, tlsConn)
			}()

			rawConn, err := stdnet.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
			nextProtos := []string{"h2", "http/1.1"}
			if http11 {
				nextProtos = []string{"http/1.1"}
			}
			conn, err := handshakeUClient(context.Background(), rawConn, &gotls.Config{
				ServerName:                     "inner.example",
				NextProtos:                     nextProtos,
				InsecureSkipVerify:             true,
				EncryptedClientHelloConfigList: list,
			}, &utls.HelloChrome_Auto, http11)
			if err != nil {
				rawConn.Close()
				t.Fatalf("handshake: %v", err)
			}
			defer conn.Close()
			server := <-states
			if server.err != nil {
				t.Fatalf("server: %v", server.err)
			}
			if !server.state.ECHAccepted || server.state.ServerName != "inner.example" {
				t.Fatalf("ECH accepted = %v, server name %q", server.state.ECHAccepted, server.state.ServerName)
			}
			want := "h2"
			if http11 {
				want = "http/1.1"
			}
			if got := server.state.NegotiatedProtocol; got != want {
				t.Fatalf("negotiated %q, want %q", got, want)
			}
		})
	}
}

// closeRecorder reports whether the connection it wraps was closed.
type closeRecorder struct {
	stdnet.Conn
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// The gRPC credentials own the connection they are given: when the hello
// cannot be built they close it, as they do when the handshake fails.
func TestGrpcUtlsClosesOnConstructionFailure(t *testing.T) {
	client, server := stdnet.Pipe()
	raw := &closeRecorder{Conn: client}
	defer raw.Close()
	defer server.Close()
	credentials := xraytls.NewGrpcUtls(&gotls.Config{ServerName: "localhost"}, &utls.HelloChrome_100_PSK)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, _, err := credentials.ClientHandshake(ctx, "localhost:443", raw)
	if err == nil {
		conn.Close()
		t.Fatal("a PSK fingerprint without a session built a hello")
	}
	if !raw.closed.Load() {
		t.Fatalf("ClientHandshake failed with %v and left its connection open", err)
	}
}

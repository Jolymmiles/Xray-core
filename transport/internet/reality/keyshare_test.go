package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"golang.org/x/crypto/hkdf"
)

const keyShareTestServerName = "localhost"

// startCoverTarget runs the TLS 1.3 site REALITY falls back to for
// unauthenticated clients. It selects X25519 without a HelloRetryRequest,
// which REALITY cannot mirror, so a handshake completes exactly when REALITY
// authenticated the client. It returns the site's address and its leaf
// certificate, which is what a client that was turned away must be shown.
func startCoverTarget(t *testing.T) (address string, leaf []byte) {
	t.Helper()
	generated, _ := cert.MustGenerate(nil, cert.CommonName(keyShareTestServerName))
	certificate, err := gotls.X509KeyPair(generated.ToPEM())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates:     []gotls.Certificate{certificate},
		MinVersion:       gotls.VersionTLS13,
		CurvePreferences: []gotls.CurveID{gotls.X25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String(), certificate.Certificate[0]
}

// helloShape rewrites the uTLS Chrome hello before the REALITY session ID is
// sealed into it.
type helloShape func(t *testing.T, uConn *utls.UConn)

func keepHello(*testing.T, *utls.UConn) {}

// withoutHybridGroup removes X25519MLKEM768 from supported_groups and
// key_share, the hello sing-box sends for REALITY with a Chrome fingerprint.
func withoutHybridGroup(t *testing.T, uConn *utls.UConn) {
	t.Helper()
	dropHybridKeyShare(t, uConn)
	for _, extension := range uConn.Extensions {
		if curves, ok := extension.(*utls.SupportedCurvesExtension); ok {
			curves.Curves = slices.DeleteFunc(curves.Curves, func(curve utls.CurveID) bool {
				return curve == utls.X25519MLKEM768
			})
		}
	}
	rebuildHello(t, uConn)
}

// withoutHybridKeyShare keeps advertising X25519MLKEM768 but omits its key
// share, which no browser that offers the hybrid group does.
func withoutHybridKeyShare(t *testing.T, uConn *utls.UConn) {
	t.Helper()
	dropHybridKeyShare(t, uConn)
	rebuildHello(t, uConn)
}

// classicKeyShareFirst sends the X25519 key share before the hybrid one,
// an order upstream treats as a strange hello.
func classicKeyShareFirst(t *testing.T, uConn *utls.UConn) {
	t.Helper()
	for _, extension := range uConn.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			slices.SortStableFunc(shares.KeyShares, func(a, b utls.KeyShare) int {
				return boolOrder(a.Group != utls.X25519) - boolOrder(b.Group != utls.X25519)
			})
		}
	}
	rebuildHello(t, uConn)
	shares := uConn.HandshakeState.Hello.KeyShares
	if len(shares) == 0 || shares[0].Group != utls.X25519 || !slices.ContainsFunc(shares, func(share utls.KeyShare) bool {
		return share.Group == utls.X25519MLKEM768
	}) {
		t.Fatalf("hello key shares were not reordered: %v", shares)
	}
}

func boolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}

func dropHybridKeyShare(t *testing.T, uConn *utls.UConn) {
	t.Helper()
	for _, extension := range uConn.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			shares.KeyShares = slices.DeleteFunc(shares.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
		}
	}
}

func rebuildHello(t *testing.T, uConn *utls.UConn) {
	t.Helper()
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
}

// dialREALITY performs the client side of UClient with a reshaped hello. It
// reports whether the server proved it authenticated the client, and the
// leaf certificate the client was shown, nil if it was shown none.
func dialREALITY(t *testing.T, conn stdnet.Conn, config *Config, shape helloShape) (verified bool, leaf []byte) {
	t.Helper()
	uConn := &UConn{Config: config, ServerName: config.ServerName}
	uConn.UConn = utls.UClient(conn, &utls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				leaf = rawCerts[0]
			}
			return uConn.VerifyPeerCertificate(rawCerts, verifiedChains)
		},
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	shape(t, uConn.UConn)

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0] = core.Version_x
	hello.SessionId[1] = core.Version_y
	hello.SessionId[2] = core.Version_z
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], config.ShortId)
	publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if uConn.AuthKey, err = ecdhe.ECDH(publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
		t.Fatal(err)
	}
	crypto.NewAesGcm(uConn.AuthKey).Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = uConn.HandshakeContext(ctx)
	return uConn.Verified, leaf
}

// headConn keeps the first bytes read from a connection: a TLS record
// header's worth. It embeds the interface, not the *net.TCPConn, so that
// io.Copy has to read through it.
type headConn struct {
	stdnet.Conn
	mu   sync.Mutex
	head []byte
}

const headLen = 5

func (c *headConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.head = append(c.head, b[:min(n, headLen-len(c.head))]...)
	c.mu.Unlock()
	return n, err
}

// CloseWrite is what REALITY's Server asks of the target's connection.
func (c *headConn) CloseWrite() error {
	return c.Conn.(*stdnet.TCPConn).CloseWrite()
}

func (c *headConn) first() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.head)
}

// keyShareResult is what one handshake showed. fromCover says the client was
// shown the cover target's certificate: the server forwarded it there, as it
// must a client it turns away, and did not drop it. clientHead and coverHead
// are the first bytes the client read and the first the server read from the
// cover target in that session: equal when the client saw the cover target's
// reply and nothing of the server's own before it.
type keyShareResult struct {
	clientVerified, serverAccepted, fromCover bool
	clientHead, coverHead                     []byte
}

// runKeyShareHandshake runs one REALITY server handshake against a client
// whose hello was reshaped. requireMLKEM is the server's "requireMlkem".
func runKeyShareHandshake(t *testing.T, shape helloShape, requireMLKEM bool) keyShareResult {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cover, coverLeaf := startCoverTarget(t)
	serverConfig := (&Config{
		Dest:        cover,
		Type:        "tcp",
		ServerNames: []string{keyShareTestServerName},
		PrivateKey:  privateKey.Bytes(),
		ShortIds:    [][]byte{shortID},

		RequireMlkem: requireMLKEM,
	}).GetREALITYConfig()
	detectCoverRecords(t, serverConfig)
	// From here on the connection to the cover target is this session's.
	var coverConn *headConn
	dialCover := serverConfig.DialContext
	serverConfig.DialContext = func(ctx context.Context, network, address string) (stdnet.Conn, error) {
		conn, err := dialCover(ctx, network, address)
		if err != nil {
			return nil, err
		}
		coverConn = &headConn{Conn: conn}
		return coverConn, nil
	}
	clientConfig := &Config{
		ServerName: keyShareTestServerName,
		PublicKey:  privateKey.PublicKey().Bytes(),
		ShortId:    shortID,
	}

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		realityConn, err := Server(conn, serverConfig)
		if err == nil {
			_ = realityConn.Close()
		}
		serverResult <- err
	}()

	dialed, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := &headConn{Conn: dialed}
	clientVerified, leaf := dialREALITY(t, conn, clientConfig, shape)
	_ = conn.Close()
	select {
	case err := <-serverResult:
		// The server has returned, so it dialed the cover target long ago.
		return keyShareResult{
			clientVerified: clientVerified,
			serverAccepted: err == nil,
			fromCover:      bytes.Equal(leaf, coverLeaf),
			clientHead:     conn.first(),
			coverHead:      coverConn.first(),
		}
	case <-time.After(10 * time.Second):
		t.Fatal(errors.New("REALITY server handshake did not finish"))
		return keyShareResult{}
	}
}

// detectCoverRecords does what the RAW listener does at startup: measure the
// cover target's post-handshake records, which the server replays after an
// authenticated handshake. It waits until every ALPN variant is measured.
func detectCoverRecords(t *testing.T, config *reality.Config) {
	t.Helper()
	reality.DetectPostHandshakeRecordsLens(config)
	deadline := time.Now().Add(10 * time.Second)
	for alpn := range 3 {
		key := config.Dest + " " + keyShareTestServerName + " " + strconv.Itoa(alpn)
		for {
			if value, ok := reality.GlobalPostHandshakeRecordsLens.Load(key); ok {
				if _, measured := value.([]int); measured {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("cover target records for %q were not measured", key)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestREALITYServerKeyShareAcceptance(t *testing.T) {
	tests := []struct {
		name         string
		shape        helloShape
		requireMLKEM bool
		accept       bool
	}{
		{name: "chrome hybrid key share", shape: keepHello, accept: true},
		{name: "hybrid group not offered", shape: withoutHybridGroup, accept: true},
		{name: "hybrid group offered without key share", shape: withoutHybridKeyShare, accept: false},
		{name: "classic key share before hybrid", shape: classicKeyShareFirst, accept: false},
		// "requireMlkem" is upstream's rule: no hello without the hybrid key
		// share authenticates.
		{name: "required, chrome hybrid key share", shape: keepHello, requireMLKEM: true, accept: true},
		{name: "required, hybrid group not offered", shape: withoutHybridGroup, requireMLKEM: true, accept: false},
		{name: "required, hybrid group offered without key share", shape: withoutHybridKeyShare, requireMLKEM: true, accept: false},
		{name: "required, classic key share before hybrid", shape: classicKeyShareFirst, requireMLKEM: true, accept: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runKeyShareHandshake(t, test.shape, test.requireMLKEM)
			if got.serverAccepted != test.accept || got.clientVerified != test.accept {
				t.Fatalf("server accepted = %v, client verified = %v, want both %v", got.serverAccepted, got.clientVerified, test.accept)
			}
			// What a prober sees of a rejection is the cover target; a
			// connection dropped instead would tell it apart.
			if got.fromCover == test.accept {
				if test.accept {
					t.Fatal("accepted hello was answered with the cover target's certificate")
				}
				t.Fatal("rejected hello was not answered by the cover target's certificate")
			}
			if test.accept {
				return
			}
			// And it sees the cover target's reply from its first byte: a
			// server that put a record of its own before it would be told
			// apart as well, though the client still gets the certificate.
			if len(got.coverHead) != headLen || !bytes.Equal(got.clientHead, got.coverHead) {
				t.Fatalf("rejected hello response starts %x; cover starts %x", got.clientHead, got.coverHead)
			}
		})
	}
}

package proxy

import (
	gotls "crypto/tls"
	stdnet "net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	realitytls "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestResolveVisionCarrierCommonConnection(t *testing.T) {
	tests := []struct {
		name           string
		connection     *encryption.CommonConn
		outer          func(testing.TB) stdnet.Conn
		wantDirectCopy bool
	}{
		{
			name:           "raw transport",
			connection:     &encryption.CommonConn{},
			outer:          func(testing.TB) stdnet.Conn { return new(stdnet.TCPConn) },
			wantDirectCopy: true,
		},
		{
			name:           "xor encryption",
			connection:     &encryption.CommonConn{Conn: &encryption.XorConn{}},
			outer:          func(testing.TB) stdnet.Conn { return new(stdnet.TCPConn) },
			wantDirectCopy: false,
		},
		{
			name:       "non-raw transport",
			connection: &encryption.CommonConn{},
			outer: func(t testing.TB) stdnet.Conn {
				connection, peer := stdnet.Pipe()
				t.Cleanup(func() {
					_ = connection.Close()
					_ = peer.Close()
				})
				return connection
			},
			wantDirectCopy: false,
		},
	}

	resolvers := []struct {
		name    string
		resolve func(stdnet.Conn, stdnet.Conn) VisionCarrier
	}{
		{name: "inbound", resolve: func(connection, outer stdnet.Conn) VisionCarrier {
			return ResolveInboundVisionCarrier(connection, outer)
		}},
		{name: "outbound", resolve: func(connection, outer stdnet.Conn) VisionCarrier {
			return ResolveOutboundVisionCarrier(connection, outer)
		}},
	}
	for _, test := range tests {
		for _, resolver := range resolvers {
			t.Run(test.name+"/"+resolver.name, func(t *testing.T) {
				wantInput, wantRawInput, ok := VisionBuffers(test.connection)
				if !ok {
					t.Fatal("CommonConn fixture does not expose Vision buffers")
				}
				carrier := resolver.resolve(test.connection, test.outer(t))
				input, rawInput, ok := carrier.Buffers()
				if !ok {
					t.Fatal("VisionCarrier.Buffers() rejected CommonConn")
				}
				if input != wantInput || rawInput != wantRawInput {
					t.Fatal("VisionCarrier.Buffers() changed Vision buffer identity")
				}
				if carrier.CanSpliceCopy() != test.wantDirectCopy {
					t.Fatalf("CanSpliceCopy() = %t, want %t", carrier.CanSpliceCopy(), test.wantDirectCopy)
				}
				if version, invalid := carrier.InvalidTLSVersion(); invalid {
					t.Fatalf("InvalidTLSVersion() = (%d, true), want valid", version)
				}
			})
		}
	}
}

func TestResolveVisionCarrierRejectsInvalidTLSVersion(t *testing.T) {
	connection, peer := stdnet.Pipe()
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})
	tlsConnection := &xraytls.Conn{Conn: gotls.Client(connection, &gotls.Config{})}

	carrier := ResolveOutboundVisionCarrier(tlsConnection, tlsConnection)
	version, invalid := carrier.InvalidTLSVersion()
	if !invalid || version != 0 {
		t.Fatalf("InvalidTLSVersion() = (%d, %t), want (0, true)", version, invalid)
	}
}

func TestResolveVisionCarrierSecureTransportAdapters(t *testing.T) {
	tests := []struct {
		name            string
		newConnection   func(testing.TB) stdnet.Conn
		wantInbound     bool
		wantOutbound    bool
		wantTLS13Reject bool
	}{
		{
			name: "TLS",
			newConnection: func(t testing.TB) stdnet.Conn {
				connection, peer := stdnet.Pipe()
				t.Cleanup(func() {
					_ = connection.Close()
					_ = peer.Close()
				})
				return &xraytls.Conn{Conn: gotls.Server(connection, &gotls.Config{})}
			},
			wantInbound:     true,
			wantOutbound:    true,
			wantTLS13Reject: true,
		},
		{
			name: "uTLS client",
			newConnection: func(t testing.TB) stdnet.Conn {
				connection, peer := stdnet.Pipe()
				t.Cleanup(func() {
					_ = connection.Close()
					_ = peer.Close()
				})
				return &xraytls.UConn{UConn: utls.UClient(connection, &utls.Config{}, utls.HelloChrome_Auto)}
			},
			wantOutbound:    true,
			wantTLS13Reject: true,
		},
		{
			name:          "REALITY server",
			newConnection: func(testing.TB) stdnet.Conn { return &xrayreality.Conn{Conn: new(realitytls.Conn)} },
			wantInbound:   true,
		},
		{
			name: "REALITY client",
			newConnection: func(t testing.TB) stdnet.Conn {
				connection, peer := stdnet.Pipe()
				t.Cleanup(func() {
					_ = connection.Close()
					_ = peer.Close()
				})
				return &xrayreality.UConn{UConn: utls.UClient(connection, &utls.Config{}, utls.HelloChrome_Auto)}
			},
			wantOutbound: true,
		},
	}

	for _, test := range tests {
		connection := test.newConnection(t)
		roles := []struct {
			name    string
			carrier VisionCarrier
			want    bool
		}{
			{name: "inbound", carrier: ResolveInboundVisionCarrier(connection, connection), want: test.wantInbound},
			{name: "outbound", carrier: ResolveOutboundVisionCarrier(connection, connection), want: test.wantOutbound},
		}
		for _, role := range roles {
			t.Run(test.name+"/"+role.name, func(t *testing.T) {
				if role.carrier.Supported() != role.want {
					t.Fatalf("Supported() = %t, want %t", role.carrier.Supported(), role.want)
				}
				if !role.want {
					if _, _, ok := role.carrier.Buffers(); ok {
						t.Fatal("Buffers() accepted carrier in the wrong direction")
					}
					if version, invalid := role.carrier.InvalidTLSVersion(); invalid {
						t.Fatalf("wrong-direction carrier exposed TLS version %d", version)
					}
					return
				}
				if _, _, ok := role.carrier.Buffers(); !ok {
					t.Fatal("Buffers() rejected supported secure carrier")
				}
				if !role.carrier.CanSpliceCopy() {
					t.Fatal("supported secure carrier disabled direct copy")
				}
				version, invalid := role.carrier.InvalidTLSVersion()
				if invalid != test.wantTLS13Reject {
					t.Fatalf("InvalidTLSVersion() = (%d, %t), want invalid=%t", version, invalid, test.wantTLS13Reject)
				}
			})
		}
	}
}

func TestVisionCarrierReadsTLSVersionAtValidationTime(t *testing.T) {
	generatedCertificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, privateKeyPEM := generatedCertificate.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse generated TLS certificate: %v", err)
	}

	clientRaw, serverRaw := stdnet.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	deadline := time.Now().Add(3 * time.Second)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS13,
		MaxVersion:         gotls.VersionTLS13,
	})
	serverTLS := gotls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		MinVersion:   gotls.VersionTLS13,
		MaxVersion:   gotls.VersionTLS13,
	})
	wrappedClient := &xraytls.Conn{Conn: clientTLS}
	carrier := ResolveOutboundVisionCarrier(wrappedClient, wrappedClient)
	if version, invalid := carrier.InvalidTLSVersion(); !invalid || version != 0 {
		t.Fatalf("pre-handshake InvalidTLSVersion() = (%d, %t), want (0, true)", version, invalid)
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS 1.3 handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server TLS 1.3 handshake: %v", err)
	}
	if version, invalid := carrier.InvalidTLSVersion(); invalid || version != gotls.VersionTLS13 {
		t.Fatalf("post-handshake InvalidTLSVersion() = (%d, %t), want (%d, false)", version, invalid, gotls.VersionTLS13)
	}
}

type wrappedVisionCarrier struct {
	stdnet.Conn
}

func TestResolveVisionCarrierRejectsExtraWrapperDepth(t *testing.T) {
	connection, peer := stdnet.Pipe()
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})
	tlsConnection := &xraytls.Conn{Conn: gotls.Client(connection, &gotls.Config{})}
	wrapper := &wrappedVisionCarrier{Conn: tlsConnection}

	if ResolveInboundVisionCarrier(wrapper, wrapper).Supported() {
		t.Fatal("inbound accepted TLS through an extra wrapper")
	}
	if ResolveOutboundVisionCarrier(wrapper, wrapper).Supported() {
		t.Fatal("outbound accepted TLS through an extra wrapper")
	}
}

func TestResolveVisionCarrierRejectsUnsupportedConnection(t *testing.T) {
	connection, peer := stdnet.Pipe()
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})

	carriers := []VisionCarrier{
		ResolveInboundVisionCarrier(connection, connection),
		ResolveOutboundVisionCarrier(connection, connection),
	}
	for _, carrier := range carriers {
		if carrier.Supported() {
			t.Fatal("unsupported connection was classified as a Vision carrier")
		}
		if _, _, ok := carrier.Buffers(); ok {
			t.Fatal("VisionCarrier.Buffers() accepted unsupported carrier")
		}
		if version, invalid := carrier.InvalidTLSVersion(); invalid {
			t.Fatalf("unsupported carrier changed the deferred TLS gate: version=%d", version)
		}
	}
}

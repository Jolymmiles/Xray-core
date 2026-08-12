package tcp

import (
	gotls "crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type presenceListener struct {
	conn net.Conn
}

func (l *presenceListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, errors.New("use of closed network connection")
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (*presenceListener) Close() error   { return nil }
func (*presenceListener) Addr() net.Addr { return &net.TCPAddr{} }

type presenceRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *presenceRemoteConn) RemoteAddr() net.Addr { return c.remote }

type hidingAuth struct{}

func (hidingAuth) Client(conn net.Conn) net.Conn { return &hidingConn{Conn: conn} }
func (hidingAuth) Server(conn net.Conn) net.Conn { return &hidingConn{Conn: conn} }

type hidingConn struct {
	net.Conn
}

func TestTCPListenerPreservesPhysicalPeerAcrossAuthenticator(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	accepted := make(chan stat.Connection, 1)
	listener := &Listener{
		listener:   &presenceListener{conn: capturedPresenceConn(server)},
		authConfig: hidingAuth{},
		addConn: func(conn stat.Connection) {
			accepted <- conn
		},
	}
	go listener.keepAccepting()
	assertAcceptedPhysicalPeer(t, <-accepted)
}

func TestTCPListenerPreservesPhysicalPeerAcrossTLS(t *testing.T) {
	generatedCertificate, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, privateKeyPEM := generatedCertificate.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	accepted := make(chan stat.Connection, 1)
	listener := &Listener{
		listener:  &presenceListener{conn: capturedPresenceConn(server)},
		tlsConfig: &gotls.Config{Certificates: []gotls.Certificate{certificate}},
		addConn: func(conn stat.Connection) {
			accepted <- conn
		},
	}
	go listener.keepAccepting()
	serverConn := <-accepted
	assertAcceptedPhysicalPeer(t, serverConn)

	serverWrite := make(chan error, 1)
	go func() {
		_, err := serverConn.Write([]byte{'x'})
		serverWrite <- err
	}()
	clientTLS := gotls.Client(client, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	_ = clientTLS.SetReadDeadline(time.Now().Add(2 * time.Second))
	marker := make([]byte, 1)
	if _, err := io.ReadFull(clientTLS, marker); err != nil {
		t.Fatal(err)
	}
	if err := <-serverWrite; err != nil {
		t.Fatal(err)
	}
}

func capturedPresenceConn(conn net.Conn) net.Conn {
	return corenet.CapturePhysicalPeer(&presenceRemoteConn{
		Conn:   conn,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.29"), Port: 443},
	})
}

func assertAcceptedPhysicalPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	peer, ok := corenet.PhysicalPeer(conn)
	if !ok || peer.String() != "192.0.2.29:443" {
		t.Fatalf("accepted physical peer = %v, ok=%v", peer, ok)
	}
}

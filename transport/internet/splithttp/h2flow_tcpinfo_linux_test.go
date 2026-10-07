//go:build linux

package splithttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func testCert(t *testing.T) gotls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFlowTCPStats checks that the kernel TCP stats are reachable through the
// wrappers an XHTTP connection really has: TLS, PROXY protocol and stats.
func TestFlowTCPStats(t *testing.T) {
	cert := testCert(t)
	for _, tc := range []struct {
		name  string
		proxy bool
		stats bool
	}{{"tls", false, false}, {"proxy+tls", true, false}, {"stats+tls", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var l net.Listener = ln
			if tc.proxy {
				l = &proxyproto.Listener{Listener: ln}
			}
			got := make(chan net.Conn, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					got <- nil
					return
				}
				if tc.stats {
					c = &stat.CounterConnection{Connection: c}
				}
				s := gotls.Server(c, &gotls.Config{Certificates: []gotls.Certificate{cert}})
				if s.Handshake() != nil {
					got <- nil
					return
				}
				got <- s
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if tc.proxy {
				c.Write([]byte("PROXY TCP4 192.0.2.1 192.0.2.2 1111 2222\r\n"))
			}
			cl := gotls.Client(c, &gotls.Config{InsecureSkipVerify: true})
			if err := cl.Handshake(); err != nil {
				t.Fatal(err)
			}
			s := <-got
			if s == nil {
				t.Fatal("server handshake failed")
			}
			defer s.Close()
			rc := rawTCP(s)
			if rc == nil {
				t.Fatal("no raw TCP socket under the connection")
			}
			st, ok := readTCPStats(rc)
			if !ok || st.rtt <= 0 || st.minRTT <= 0 {
				t.Fatalf("no TCP stats: %+v %v", st, ok)
			}
		})
	}
}

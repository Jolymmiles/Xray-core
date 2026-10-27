package refreshtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/masque"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/refreshtest"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// helloPeer is a TCP server that reads the first bytes of each connection, a
// TLS dialer's ClientHello, reports them and closes the connection.
func helloPeer(t *testing.T) (net.Destination, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	hellos := make(chan struct{}, 64)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				var record [1]byte
				if n, _ := conn.Read(record[:]); n == 1 && record[0] == 0x16 {
					select {
					case hellos <- struct{}{}:
					default:
					}
				}
			}()
		}
	}()
	return net.DestinationFromAddr(listener.Addr()), hellos
}

// closedUDPPort is a loopback port nothing answers UDP on. Transports over UDP
// are dialed with a TCP destination too.
func closedUDPPort(t *testing.T) net.Destination {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	port := net.Port(conn.LocalAddr().(*net.UDPAddr).Port)
	conn.Close()
	return net.TCPDestination(net.LocalHostIP, port)
}

// Every dialer builds its TLS config for a connection without the certificate
// refresh workers a listener's config starts: a client never selects one of
// its certificates, and a worker started per dial outlives the connection.
func TestDialersStartNoCertificateRefreshWorkers(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		udp      bool
		alpn     []string
	}{
		{name: "tcp", protocol: "tcp"},
		{name: "websocket", protocol: "websocket"},
		{name: "httpupgrade", protocol: "httpupgrade"},
		{name: "grpc", protocol: "grpc"},
		{name: "splithttp", protocol: "splithttp", alpn: []string{"h2"}},
		{name: "masque-h2", protocol: "masque", alpn: []string{"h2"}},
		{name: "masque-h3", protocol: "masque", udp: true},
		{name: "mkcp", protocol: kcp.ProtocolName, udp: true},
		{name: "hysteria", protocol: "hysteria", udp: true},
	}
	for _, usage := range []tls.Certificate_Usage{tls.Certificate_ENCIPHERMENT, tls.Certificate_AUTHORITY_ISSUE} {
		for _, c := range cases {
			t.Run(c.name+"/"+usage.String(), func(t *testing.T) {
				config, baseline := refreshtest.Config(t, usage)
				config.ServerName = "dns.example"
				config.NextProtocol = c.alpn
				protocolSettings, err := internet.CreateTransportConfig(c.protocol)
				if err != nil {
					t.Fatal(err)
				}
				settings := &internet.MemoryStreamConfig{
					ProtocolName: c.protocol, ProtocolSettings: protocolSettings,
					SecurityType: "tls", SecuritySettings: config,
				}
				var dest net.Destination
				var hellos <-chan struct{}
				if c.udp {
					dest = closedUDPPort(t)
				} else {
					dest, hellos = helloPeer(t)
				}
				for range 3 {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					conn, err := internet.Dial(ctx, dest, settings)
					if err == nil {
						conn.Close()
					} else {
						t.Log(err)
					}
					cancel()
				}
				// a ClientHello proves the dialer built its TLS config
				if hellos != nil {
					select {
					case <-hellos:
					case <-time.After(5 * time.Second):
						t.Fatal("the dialer sent no ClientHello")
					}
				}
				if workers := refreshtest.Workers() - baseline; workers != 0 {
					t.Fatalf("three dials started %d certificate refresh workers", workers)
				}
			})
		}
	}
}

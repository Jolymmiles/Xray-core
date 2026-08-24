package httpupgrade_test

import (
	"bufio"
	"context"
	"fmt"
	stdnet "net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Test_listenHTTPUpgradeAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func Test_listenHTTPUpgradeAndDialWithHeaders(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
			Header: map[string]string{
				"User-Agent": "Mozilla",
			},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listenPort := tcp.PickPort()
	physicalPeer := make(chan string, 1)
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
		SocketSettings: &internet.SocketConfig{
			TrustedXForwardedFor: []string{"X-Forwarded-For"},
		},
	}, func(conn stat.Connection) {
		if peer, ok := net.PhysicalPeer(conn); ok {
			physicalPeer <- peer.String()
		} else {
			physicalPeer <- ""
		}
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			// common.Must(err)
			if err != nil {
				return
			}

			_, err = c.Write([]byte(c.RemoteAddr().String()))
			common.Must(err)
		}(conn)
	})
	common.Must(err)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "1.1.1.1:0" {
		t.Error("response: ", string(b[:n]))
	}
	if got := <-physicalPeer; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("physical peer = %q, want loopback socket peer", got)
	}

	common.Must(listen.Close())
}

func TestAcceptedProxyPeerSurvivesTrustedXFFRewrite(t *testing.T) {
	listenPort := tcp.PickPort()
	type result struct {
		physical  string
		accepted  string
		effective string
	}
	results := make(chan result, 1)
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
		SocketSettings: &internet.SocketConfig{
			AcceptProxyProtocol:  true,
			TrustedXForwardedFor: []string{"X-Forwarded-For"},
		},
	}, func(conn stat.Connection) {
		var got result
		if peer, ok := net.PhysicalPeer(conn); ok {
			got.physical = peer.String()
		}
		if peer, ok := net.AcceptedProxyPeer(conn); ok {
			got.accepted = peer.String()
		}
		got.effective = conn.RemoteAddr().String()
		results <- got
		_ = conn.Close()
	})
	common.Must(err)
	t.Cleanup(func() { _ = listen.Close() })

	conn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "PROXY TCP4 198.51.100.7 127.0.0.1 12345 %d\r\nGET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-For: 203.0.113.99\r\n\r\n", listenPort)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/httpupgrade", listenPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %s", response.Status)
	}

	got := <-results
	if got.accepted != "198.51.100.7" {
		t.Fatalf("accepted PROXY peer = %q, want 198.51.100.7", got.accepted)
	}
	if got.effective != "203.0.113.99:0" {
		t.Fatalf("effective remote = %q, want trusted XFF", got.effective)
	}
	if !strings.HasPrefix(got.physical, "127.0.0.1:") {
		t.Fatalf("physical peer = %q, want raw loopback socket peer", got.physical)
	}
}

func Test_listenHTTPUpgradeAndDial_TLS(t *testing.T) {
	listenPort := tcp.PickPort()
	if runtime.GOARCH == "arm64" {
		return
	}

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrades",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			_ = conn.Close()
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_ = conn.Close()

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}

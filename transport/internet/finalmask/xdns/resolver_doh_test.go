package xdns

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func h3ResolverConfig(congestion string) *ResolverProto {
	return &ResolverProto{
		Type:       "https",
		Addr:       "https://192.0.2.53/dns-query",
		Worker:     1,
		TlsConfig:  &tls.Config{ServerName: "dns.example", NextProtocol: []string{"h3"}},
		QuicConfig: &internet.QuicParams{Congestion: congestion, BrutalUp: 1 << 20},
	}
}

// A QUIC dial that never completes is canceled by Close; the socket it dialed
// has to be closed with it rather than left to the garbage collector.
func TestDOHResolverH3ClosesTheSocketOfAFailedDial(t *testing.T) {
	dialed := make(chan *trackedPacketConn, 1)
	dialer := &finalmask.Dialer{
		DialUDP: func(net.Destination) (net.Conn, error) {
			socket := &trackedPacketConn{blockingPacketConn: newBlockingPacketConn()}
			dialed <- socket
			return &net.PacketConnWrapper{
				PacketConn: socket,
				Dest:       &net.UDPAddr{IP: net.IP{192, 0, 2, 53}, Port: 443},
			}, nil
		},
	}
	resolver, err := NewDOHResolver(h3ResolverConfig(""), dialer)
	if err != nil {
		t.Fatal(err)
	}

	resolver.Send([]byte("query"))
	var socket *trackedPacketConn
	select {
	case socket = <-dialed:
	case <-time.After(5 * time.Second):
		resolver.Close()
		t.Fatal("the h3 resolver never dialed")
	}
	resolver.Close()

	select {
	case <-socket.closed:
	case <-time.After(5 * time.Second):
		socket.Close()
		t.Fatal("the socket of a dial that Close canceled was left open")
	}
}

// "brutal" is valid QUIC congestion for Hysteria, where the server agrees to
// it. A DoH server does not, and the h3 dial panicked on it in a goroutine
// nothing recovers, taking the process down on the first query.
func TestNewDOHResolverRejectsBrutalCongestion(t *testing.T) {
	dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		t.Error("a resolver with an unsupported congestion control dialed")
		return nil, io.ErrClosedPipe
	}}
	if resolver, err := NewDOHResolver(h3ResolverConfig("brutal"), dialer); err == nil {
		resolver.Close()
		t.Fatal(`NewDOHResolver accepted "congestion": "brutal"`)
	}
	for _, congestion := range []string{"", "reno", "bbr", "force-brutal"} {
		resolver, err := NewDOHResolver(h3ResolverConfig(congestion), dialer)
		if err != nil {
			t.Fatalf("NewDOHResolver refused %q: %v", congestion, err)
		}
		resolver.Close()
	}
}

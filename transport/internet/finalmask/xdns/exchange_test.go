package xdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// The exchange tests come from TaiLerV's sync/upstream-2026-10-02 branch
// (b128cdb1 and its loopback test), adapted to this tree.

// testDialer reaches resolvers over plain loopback sockets, like the
// finalmask dialer without masks.
func testDialer() *finalmask.Dialer {
	return &finalmask.Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return stdnet.Dial("tcp", dest.NetAddr())
		},
		DialUDP: func(dest net.Destination) (net.Conn, error) {
			conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return &net.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}}, nil
		},
	}
}

// closeWithin fails the test if closeFn, the Close of name, does not return
// within 3 seconds.
func closeWithin(t *testing.T, name string, closeFn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		closeFn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s Close did not return", name)
	}
}

// runExchange sends rounds of datagrams from client to server and back,
// checking that each one arrives exactly once, then checks that both sides
// close. Callers close them in cleanup too, which also covers a failed check.
func runExchange(t *testing.T, client, server net.PacketConn, rounds int) {
	t.Helper()
	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for range rounds {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				serverDone <- err
				return
			}
			reply := append([]byte("pong:"), buf[:n]...)
			if _, err := server.WriteTo(reply, addr); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	buf := make([]byte, 4096)
	for i := range rounds {
		want := []byte{'p', 'i', 'n', 'g', byte('0' + i)}
		if _, err := client.WriteTo(want, &net.UDPAddr{IP: stdnet.IPv4zero}); err != nil {
			t.Fatal(err)
		}
		readDone := make(chan error, 1)
		go func() {
			n, _, err := client.ReadFrom(buf)
			if err == nil && !bytes.Equal(buf[:n], append([]byte("pong:"), want...)) {
				err = errors.New("unexpected reply " + string(buf[:n]))
			}
			readDone <- err
		}()
		select {
		case err := <-readDone:
			if err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: no reply through the resolver", i)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	closeWithin(t, "XDNS client", func() { _ = client.Close() })
	closeWithin(t, "XDNS server", func() { _ = server.Close() })
}

// A client and server joined through a loopback UDP resolver must carry data
// both ways while both sides read, write and close.
func TestUDPResolverExchangeAndClose(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	clientConfig := testServerConfig()
	clientConfig.Resolvers = []*ResolverProto{{Type: "udp", Addr: raw.LocalAddr().String()}}
	client, err := NewClient(clientConfig, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	runExchange(t, client, server, 5)
}

// startTCPForwarder relays DNS over TCP (RFC 1035, Section 4.2.2) to a UDP
// DNS server, like a resolver that clients reach over TCP.
func startTCPForwarder(t *testing.T, upstream net.Addr) net.Addr {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
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
			go relayTCPToUDP(conn, upstream)
		}
	}()
	return listener.Addr()
}

// relayTCPToUDP forwards each length-prefixed query read from conn to
// upstream over UDP, and writes each reply back to conn with its length.
func relayTCPToUDP(conn stdnet.Conn, upstream net.Addr) {
	defer conn.Close()
	udp, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer udp.Close()
	var writeMu sync.Mutex
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			frame := binary.BigEndian.AppendUint16(nil, uint16(n))
			writeMu.Lock()
			_, err = conn.Write(append(frame, buf[:n]...))
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	var prefix [2]byte
	for {
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		if _, err := udp.WriteTo(query, upstream); err != nil {
			return
		}
	}
}

// The TCP resolver must frame queries and parse framed answers end to end.
func TestTCPResolverExchange(t *testing.T) {
	raw, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	server, err := NewServer(testServerConfig(), raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	forwarder := startTCPForwarder(t, raw.LocalAddr())
	clientConfig := testServerConfig()
	clientConfig.Resolvers = []*ResolverProto{{Type: "tcp", Addr: forwarder.String()}}
	client, err := NewClient(clientConfig, testDialer())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	runExchange(t, client, server, 5)
}

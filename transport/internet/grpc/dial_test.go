package grpc

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// closeCachedClients closes and forgets the gRPC clients Dial cached for
// dest.
func closeCachedClients(dest net.Destination) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for key, client := range globalDialerMap {
		if key.Destination == dest {
			_ = client.Close()
			delete(globalDialerMap, key)
		}
	}
}

// The gRPC dialer completes the uTLS handshake itself, under gRPC's connect
// context, and reports its failure as a dial error. Left to gRPC's first
// write, the same failure would surface while writing the client preface.
func TestDialCompletesUTLSHandshake(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The peer is no TLS server: it answers the ClientHello in plain HTTP.
	// Every accepted connection is closed by its handler, and the test ends
	// only after the accept loop and all handlers have returned.
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		handlers.Wait()
	})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Read(make([]byte, 512)); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			}()
		}
	}()

	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*stdnet.TCPAddr).Port))
	t.Cleanup(func() { closeCachedClients(dest) })
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{ServiceName: "not-tls"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{ServerName: "localhost", Fingerprint: "chrome"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, dest, streamSettings)
	if err == nil {
		t.Fatal("dial through a peer that does not speak TLS succeeded")
	}
	if !strings.Contains(err.Error(), "Error while dialing") || !strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		t.Fatalf("the TLS failure was not reported by the dialer: %v", err)
	}
}

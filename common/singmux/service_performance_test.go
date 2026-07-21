package singmux

import (
	"context"
	"net"
	"testing"

	X "github.com/xtls/xray-core/common/net"
	localsmux "github.com/xtls/xray-core/common/singmux/internal/mplsmux"
	"github.com/xtls/xray-core/transport"
)

type handshakeBenchmarkDispatcher struct{ *echoDispatcher }

func (*handshakeBenchmarkDispatcher) DispatchLink(context.Context, X.Destination, *transport.Link) error {
	return nil
}

func BenchmarkServiceStreamHandshake(b *testing.B) {
	service := NewService(&handshakeBenchmarkDispatcher{echoDispatcher: &echoDispatcher{target: make(chan X.Destination, 1)}})
	clientConnection, serverConnection := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	go func() { _ = service.NewConnection(ctx, serverConnection) }()
	if err := writeCarrierRequest(clientConnection, protocolSMUX, nil); err != nil {
		b.Fatal(err)
	}
	config := localsmux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := localsmux.Client(clientConnection, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = session.Close() })
	destination := X.TCPDestination(X.DomainAddress("example.com"), 443)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		stream, err := session.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		if err := writeStreamRequest(stream, 0, destination); err != nil {
			b.Fatal(err)
		}
		if err := readStreamResponse(stream); err != nil {
			b.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

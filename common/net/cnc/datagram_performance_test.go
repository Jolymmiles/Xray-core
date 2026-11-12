package cnc

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// benchmarkLink returns one datagram of size bytes per read, in a pooled
// buffer, as the pipe of a link to another outbound does.
type benchmarkLink struct{ size int32 }

func (l *benchmarkLink) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Extend(l.size)
	return buf.MultiBuffer{b}, nil
}

// BenchmarkDatagramConnectionRead measures a Read of one datagram from a
// connection for a UDP destination, as FakePacketConn reads the packets of a
// QUIC transport or of a UDP mask over sockopt.dialerProxy, and as the SOCKS,
// Shadowsocks, DNS and WireGuard outbounds read their replies. One op is one
// datagram copied into a buffer that holds it.
func BenchmarkDatagramConnectionRead(b *testing.B) {
	for _, c := range []struct{ datagram, read int }{
		{64, 1500},
		{1200, 1500},
		{1200, buf.Size + 1},
		{buf.Size, buf.Size + 1},
	} {
		b.Run(fmt.Sprintf("%d_into_%d", c.datagram, c.read), func(b *testing.B) {
			connection := NewConnection(ConnectionOutputMultiUDP(&benchmarkLink{size: int32(c.datagram)}))
			p := make([]byte, c.read)
			b.SetBytes(int64(c.datagram))
			b.ReportAllocs()
			for b.Loop() {
				if n, err := connection.Read(p); err != nil || n != c.datagram {
					b.Fatalf("read %d bytes, want %d: %v", n, c.datagram, err)
				}
			}
		})
	}
}

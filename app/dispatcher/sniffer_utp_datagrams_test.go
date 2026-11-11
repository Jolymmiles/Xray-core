package dispatcher

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

// A uTP SYN is a whole datagram. Several datagrams queued before the first
// read must not hide it: the sniffer reads the first one on its own, as the
// QUIC sniffer does, and every datagram is forwarded intact.
func TestSniffUTPReadsTheFirstDatagram(t *testing.T) {
	syn := vUTPSYN()
	for name, datagrams := range map[string][][]byte{
		"single SYN":       {syn},
		"SYN then SYN":     {syn, syn},
		"SYN then DHT":     {syn, vDHTGetPeers()},
		"DHT then SYN":     {vDHTGetPeers(), syn},
		"tracker then SYN": {vUDPTrackerConnect(), syn},
	} {
		t.Run(name, func(t *testing.T) {
			r, w := pipe.New(pipe.WithSizeLimit(32768))
			t.Cleanup(r.Interrupt)
			for _, datagram := range datagrams {
				b := buf.New()
				if _, err := b.Write(datagram); err != nil {
					b.Release()
					t.Fatal(err)
				}
				if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Fatal(err)
				}
			}
			reader := newTestCachedReader(t, r)
			result, err := sniff(context.Background(), reader, false, net.Network_UDP, newSniffer(snifferContext()))
			forwarded, readErr := reader.ReadMultiBufferTimeout(time.Millisecond)
			if readErr != nil {
				t.Fatal(readErr)
			}
			defer buf.ReleaseMulti(forwarded)
			if len(forwarded) != len(datagrams) {
				t.Fatalf("forwarded %d datagrams, want %d", len(forwarded), len(datagrams))
			}
			for i, b := range forwarded {
				if !bytes.Equal(b.Bytes(), datagrams[i]) {
					t.Fatalf("datagram %d changed", i)
				}
			}
			if err != nil || result == nil || result.Protocol() != "bittorrent" {
				t.Fatalf("sniff() = %v, %v; want bittorrent", result, err)
			}
		})
	}
}

// A datagram that only starts with a SYN is not one.
func TestSniffUTPRejectsDataInTheFirstDatagram(t *testing.T) {
	ctx := snifferContext()
	first := append(vUTPSYN(), "data"...)
	datagrams := [][]byte{first, vUTPSYN()}
	result, err := NewSniffer(ctx).SniffDatagrams(ctx, bytes.Join(datagrams, nil), datagrams, net.Network_UDP)
	if err == nil && result.Protocol() == "bittorrent" {
		t.Fatal("SYN with data in its datagram classified as bittorrent")
	}
}

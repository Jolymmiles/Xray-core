package freedom

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// linkDatagrams are a datagram above buf.Size, one that fills a regular buffer
// and a short one, as an inbound or another outbound hands them on: a buffer
// each, with the address of the packet.
func linkDatagrams() ([][]byte, buf.MultiBuffer) {
	payloads := [][]byte{bytes.Repeat([]byte{1}, 9000), bytes.Repeat([]byte{2}, buf.Size), []byte("ping")}
	address := net.UDPDestination(net.LocalHostIP, 443)
	mb := make(buf.MultiBuffer, 0, len(payloads))
	for _, payload := range payloads {
		b := buf.NewWithSize(int32(len(payload)))
		_, _ = b.Write(payload)
		b.UDP = &address
		mb = append(mb, b)
	}
	return payloads, mb
}

// wantLinkDatagrams fails unless mb holds payloads, a buffer each, without an
// address.
func wantLinkDatagrams(t *testing.T, mb buf.MultiBuffer, payloads [][]byte) {
	t.Helper()
	lengths := make([]int32, 0, len(mb))
	for _, b := range mb {
		lengths = append(lengths, b.Len())
	}
	if len(mb) != len(payloads) {
		t.Fatalf("the link carried datagrams of %v bytes, want %d datagrams", lengths, len(payloads))
	}
	for i, b := range mb {
		if !bytes.Equal(b.Bytes(), payloads[i]) {
			t.Fatalf("the link carried datagrams of %v bytes, want datagram %d of %d bytes whole", lengths, i, len(payloads[i]))
		}
		if b.UDP != nil {
			t.Fatalf("datagram %d carries the address %v across the link, want none as before", i, b.UDP)
		}
	}
}

// newLink returns a connection as transport/internet's redirect builds it for
// a UDP destination, with the end of each of its pipes that the other outbound
// holds: the reader of what freedom writes and the writer of what it reads.
func newLink(t *testing.T) (stat.Connection, *pipe.Reader, *pipe.Writer) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(uplinkWriter), cnc.ConnectionOutputMultiUDP(downlinkReader))
	t.Cleanup(func() { conn.Close() })
	return conn, uplinkReader, downlinkWriter
}

// With sockopt.dialerProxy freedom's connection is the link to another
// outbound (transport/internet's redirect), which carries buffers and has a
// TCP address for UDP too. Freedom wrote to it and read from it as a stream of
// bytes: a datagram of 9000 bytes went on as two, of 8192 and 808, and a reply
// of 9000 bytes came back as its first 8192. It hands the buffers on as they
// are, a datagram each, and counts them; the address of a packet stays behind,
// as before, so that the other outbound sends every datagram to the
// destination freedom dialed.
func TestDialerProxyLinkKeepsDatagramsWhole(t *testing.T) {
	destination := net.UDPDestination(net.LocalHostIP, 53)
	for _, counted := range []bool{false, true} {
		name := "plain"
		if counted {
			name = "with statistics"
		}
		t.Run(name+"/write", func(t *testing.T) {
			conn, reader, _ := newLink(t)
			counter := &readCounter{}
			if counted {
				conn = &stat.CounterConnection{Connection: conn, WriteCounter: counter}
			}
			payloads, mb := linkDatagrams()
			packetWriter := NewPacketWriter(context.Background(), conn, &Handler{}, nil, net.Destination{}, destination, nil)
			if err := packetWriter.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			got, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(got)
			wantLinkDatagrams(t, got, payloads)
			if want := int64(9000 + buf.Size + len("ping")); counted && counter.Value() != want {
				t.Fatalf("the statistics counted %d bytes written, want %d", counter.Value(), want)
			}
		})
		t.Run(name+"/read", func(t *testing.T) {
			conn, _, writer := newLink(t)
			counter := &readCounter{}
			if counted {
				conn = &stat.CounterConnection{Connection: conn, ReadCounter: counter}
			}
			payloads, mb := linkDatagrams()
			if err := writer.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			packetReader := NewPacketReader(context.Background(), conn, &Handler{}, nil, net.Destination{}, destination)
			got, err := packetReader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(got)
			wantLinkDatagrams(t, got, payloads)
			if want := int64(9000 + buf.Size + len("ping")); counted && counter.Value() != want {
				t.Fatalf("the statistics counted %d bytes read, want %d", counter.Value(), want)
			}
		})
	}
}

// The link takes the buffers it is written, where a socket takes their bytes,
// and a writer of the other outbound may change a buffer in place. The noise
// that the configuration gives as a packet went out in a buffer over the
// configuration's own bytes; over a link it goes out as a copy.
func TestDialerProxyLinkTakesACopyOfConfiguredNoise(t *testing.T) {
	configured := []byte("configured noise")
	conn, reader, _ := newLink(t)
	writer := &NoisePacketWriter{
		Writer:     NewPacketWriter(context.Background(), conn, &Handler{}, nil, net.Destination{}, net.UDPDestination(net.LocalHostIP, 443), nil),
		noises:     []*Noise{{Packet: configured, ApplyTo: "ip"}},
		firstWrite: true,
		remoteAddr: net.LocalHostIP,
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping"))}); err != nil {
		t.Fatal(err)
	}
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 2 || !bytes.Equal(mb[0].Bytes(), configured) || string(mb[1].Bytes()) != "ping" {
		t.Fatalf("the link carried %d buffers, want the noise and the datagram", len(mb))
	}
	mb[0].Bytes()[0] ^= 0xFF
	if string(configured) != "configured noise" {
		t.Fatalf("a change of the noise on the link changed the configured packet to %q", configured)
	}
}

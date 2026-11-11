package buf

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

// benchmarkSocket returns its datagrams in turn, one per Read, and like a UDP
// socket cuts one longer than the buffer it reads into.
type benchmarkSocket struct {
	datagrams [][]byte
	next      int
}

func (s *benchmarkSocket) Read(p []byte) (int, error) {
	n := copy(p, s.datagrams[s.next])
	s.next = (s.next + 1) % len(s.datagrams)
	return n, nil
}

// BenchmarkDatagramReaderRead measures a steady-state read of one datagram by
// DatagramReader, which reads into its scratch and copies the datagram into a
// pooled Buffer, next to PacketReader, which reads into the Buffer and which
// the outbounds used before. One op is one datagram returned and released;
// in "9000+1200" DatagramReader also drops a datagram longer than Size before
// it, which PacketReader would return cut, so that case has no PacketReader
// side.
func BenchmarkDatagramReaderRead(b *testing.B) {
	for _, c := range []struct {
		name  string
		sizes []int
	}{
		{"64", []int{64}},
		{"1200", []int{1200}},
		{"8192", []int{Size}},
		{"9000+1200", []int{9000, 1200}},
	} {
		datagrams := make([][]byte, len(c.sizes))
		for i, size := range c.sizes {
			datagrams[i] = bytes.Repeat([]byte{1}, size)
		}
		returned := int64(c.sizes[len(c.sizes)-1])
		readers := []struct {
			name string
			open func(io.Reader) Reader
		}{
			{"DatagramReader", func(r io.Reader) Reader { return &DatagramReader{Reader: r} }},
			{"PacketReader", func(r io.Reader) Reader { return &PacketReader{Reader: r} }},
		}
		if len(c.sizes) > 1 {
			readers = readers[:1]
		}
		for _, r := range readers {
			b.Run(fmt.Sprintf("%s/%s", r.name, c.name), func(b *testing.B) {
				reader := r.open(&benchmarkSocket{datagrams: datagrams})
				b.SetBytes(returned)
				b.ReportAllocs()
				for b.Loop() {
					mb, err := reader.ReadMultiBuffer()
					if err != nil || mb.Len() != int32(returned) {
						b.Fatalf("read %d bytes, want %d: %v", mb.Len(), returned, err)
					}
					ReleaseMulti(mb)
				}
			})
		}
	}
}

// BenchmarkDatagramReaderCreate measures what a session pays for its reader:
// DatagramReader holds its scratch of Size+1 bytes inline, where PacketReader
// holds only the socket. One op is one reader.
func BenchmarkDatagramReaderCreate(b *testing.B) {
	socket := &benchmarkSocket{datagrams: [][]byte{{1}}}
	b.Run("DatagramReader", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			readerBenchmarkSink = &DatagramReader{Reader: socket}
		}
	})
	b.Run("PacketReader", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			readerBenchmarkSink = &PacketReader{Reader: socket}
		}
	})
}

// BenchmarkReadDatagram measures a read of one framed datagram from a stream
// that holds it: up to Size bytes it reads into a pooled Buffer, and above it
// reads into regular Buffers and copies them into one of the datagram's size.
// One op is one datagram returned and released.
func BenchmarkReadDatagram(b *testing.B) {
	for _, size := range []int32{1200, Size, Size + 1, 16384, 32768, 32769, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			framed := make([]byte, size)
			stream := bytes.NewReader(framed)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				stream.Reset(framed)
				datagram, err := ReadDatagram(stream, size)
				if err != nil {
					b.Fatal(err)
				}
				datagram.Release()
			}
		})
	}
}

package splithttp

import (
	"bytes"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

// replayConn serves the same byte stream to Read over and over and
// discards whatever is written, so a benchmark measures only the code
// between the HTTP/2 stack and the socket.
type replayConn struct {
	net.Conn
	data []byte
	off  int
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.off == len(c.data) {
		c.off = 0
	}
	n := copy(b, c.data[c.off:])
	c.off += n
	return n, nil
}

func (c *replayConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *replayConn) Close() error                { return nil }

const benchChunk = 1 << 20

// uploadFrames is 1 MiB of client DATA on stream 1 in default-size frames,
// followed by the credit a client hands back for a download.
func uploadFrames() []byte {
	return frames(func(fr *http2.Framer) {
		writeDataSplit(fr, 1, benchChunk)
		fr.WriteWindowUpdate(0, benchChunk)
		fr.WriteWindowUpdate(1, benchChunk)
	})
}

// downloadFrames is 1 MiB of server DATA on stream 1 in default-size
// frames, followed by the credit a server hands back for an upload.
func downloadFrames() []byte {
	return frames(func(fr *http2.Framer) {
		writeDataSplit(fr, 1, benchChunk)
		fr.WriteWindowUpdate(0, benchChunk)
		fr.WriteWindowUpdate(1, benchChunk)
	})
}

// benchFlowConn returns a server-side governor whose connection already has
// SETTINGS exchanged and stream 1 open, reading from inner. Its client hands
// back credit in small steps, as Go clients do, so no guard probe runs.
func benchFlowConn(tb testing.TB, inner *replayConn) *flowConn {
	tb.Helper()
	setup := &scriptConn{}
	c := newFlowConn(setup, flowDefault, flowDefault)
	h := &flowHarness{t: tb, conn: setup, c: c}
	h.fromClientRaw([]byte(h2Preface))
	h.openStream(4 << 20)
	if h.readErr != nil {
		tb.Fatal(h.readErr)
	}
	c.mu.Lock()
	c.lastPing = c.lastPing.AddDate(100, 0, 0) // keep PINGs out of the measurement
	c.incremental = true
	c.mu.Unlock()
	c.Conn = inner
	return c
}

// BenchmarkFlowRead measures reading 1 MiB of client frames into 16 KiB
// buffers, as the HTTP/2 server's reads come in, with and without the
// governor.
func BenchmarkFlowRead(b *testing.B) {
	data := uploadFrames()
	for _, governed := range []bool{false, true} {
		name := "stock"
		if governed {
			name = "governed"
		}
		b.Run(name, func(b *testing.B) {
			inner := &replayConn{data: data}
			var r io.Reader = inner
			if governed {
				r = benchFlowConn(b, inner)
			}
			buf := make([]byte, 16<<10)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for got := 0; got < len(data); {
					n, err := r.Read(buf)
					if err != nil {
						b.Fatal(err)
					}
					got += n
				}
			}
		})
	}
}

// BenchmarkFlowWrite measures writing 1 MiB of server frames in 16 KiB
// writes, with and without the governor.
func BenchmarkFlowWrite(b *testing.B) {
	data := downloadFrames()
	for _, governed := range []bool{false, true} {
		name := "stock"
		if governed {
			name = "governed"
		}
		b.Run(name, func(b *testing.B) {
			inner := &replayConn{}
			var w io.Writer = inner
			if governed {
				w = benchFlowConn(b, inner)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for in := data; len(in) > 0; {
					n := min(len(in), 16<<10)
					if _, err := w.Write(in[:n]); err != nil {
						b.Fatal(err)
					}
					in = in[n:]
				}
			}
		})
	}
}

// TestFlowBenchStreamsAreGoverned guards the benchmarks: the governed
// connection must really parse and count the replayed frames.
func TestFlowBenchStreamsAreGoverned(t *testing.T) {
	inner := &replayConn{data: uploadFrames()}
	c := benchFlowConn(t, inner)
	buf := make([]byte, 16<<10)
	for got := 0; got < len(inner.data); {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got += n
	}
	if _, err := c.Write(downloadFrames()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.streams[1]
	if s == nil || s.upSent != benchChunk || s.downSent != benchChunk || !bytes.Equal(c.rpending, nil) {
		t.Fatalf("governor did not account the replayed frames: %+v", s)
	}
}

package splithttp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"golang.org/x/net/http2"
)

// FuzzFlowClientConn drives a client's governor through both of its paths:
// the client stack's bytes go out through Write and the server's come in
// through Read, a frame at a time, with each PING the governor sent answered
// between the server's frames, so the round trip and what follows it run:
// the models, the cuts and the server's tagged PING. Whatever either peer
// sends, the governor holds bounded state and passes every byte of data
// either way.
func FuzzFlowClientConn(f *testing.F) {
	var cl bytes.Buffer
	fc := http2.NewFramer(&cl, nil)
	fc.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	fc.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true, EndStream: true})
	fc.WriteWindowUpdate(1, 70000)
	fc.WriteWindowUpdate(0, 70000)
	fc.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x82}, EndHeaders: true})
	fc.WriteData(3, true, make([]byte, 100))
	// A stock server, which the client pings, and a governed one, whose
	// tagged PING hands the client over.
	for _, governed := range []bool{false, true} {
		var srv bytes.Buffer
		fs := http2.NewFramer(&srv, nil)
		fs.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if governed {
			var tagged [8]byte
			binary.BigEndian.PutUint32(tagged[:], flowPingTag)
			fs.WritePing(false, tagged)
		}
		fs.WriteSettings()
		fs.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true})
		// Under the 65535 the connection starts with: the client's credit
		// may come after.
		for range 3 {
			fs.WriteData(1, false, make([]byte, 16000))
		}
		fs.WriteRSTStream(3, http2.ErrCodeCancel)
		fs.WriteGoAway(1, http2.ErrCodeNo, nil)
		f.Add(cl.Bytes(), srv.Bytes(), uint8(5))
		f.Add(cl.Bytes(), srv.Bytes(), uint8(15))
	}

	f.Fuzz(fuzzFlowClient)
}

func fuzzFlowClient(t *testing.T, fromClient, fromServer []byte, cut uint8) {
	sc := &scriptConn{}
	c := newFlowClientConn(sc)
	defer c.Close()
	step := int(cut%16) + 1
	frames := serverFrames(fromServer)
	in := append([]byte(h2Preface), fromClient...)
	var toServer, toClient []byte
	scanned, cutShort := len(h2Preface), false
	buf := make([]byte, 64<<10)
	for len(in) > 0 || len(frames) > 0 {
		if len(in) > 0 {
			n := min(step, len(in))
			if _, err := c.Write(in[:n]); err != nil {
				if !c.isBroken() {
					t.Fatal(err)
				}
				break
			}
			in = in[n:]
		}
		c.wmu.Lock()
		//nolint:staticcheck // empty critical section: only waits for the holder
		c.wmu.Unlock()
		toServer = append(toServer, sc.take()...)
		// Answers go in only between whole frames outside a header
		// block, where the server's stack could send them, and not after
		// a piece that ends inside a frame.
		if !cutShort && (len(frames) == 0 || frames[0].between) {
			var pings [][8]byte
			pings, scanned = unansweredPings(toServer, scanned)
			for _, p := range pings {
				sc.feed(frames2(func(fr *http2.Framer) { fr.WritePing(true, p) }))
			}
		}
		if len(frames) > 0 {
			sc.feed(frames[0].b)
			cutShort = frames[0].partial
			frames = frames[1:]
		}
		got, err := readAvailable(c, buf)
		toClient = append(toClient, got...)
		if err != nil {
			if !c.isBroken() {
				t.Fatal(err)
			}
			break
		}
	}
	c.mu.Lock()
	streams := len(c.streams)
	c.mu.Unlock()
	if streams > len(fromClient)/h2FrameHeader+1 {
		t.Fatalf("%d streams tracked from %d input bytes", streams, len(fromClient))
	}
	if err := downCountersAgree(c); err != nil {
		t.Fatal(err)
	}
	if c.isBroken() {
		return
	}
	if len(toServer) < len(h2Preface) {
		t.Fatalf("%d bytes reached the server", len(toServer))
	}
	if sent, got := dataFrames(fromClient), dataFrames(toServer[len(h2Preface):]); !bytes.Equal(sent, got) {
		t.Fatalf("the server read %d bytes of data frames, the client sent %d", len(got), len(sent))
	}
	if sent, got := dataFrames(fromServer), dataFrames(toClient); !bytes.Equal(sent, got) {
		t.Fatalf("the client read %d bytes of data frames, the server sent %d", len(got), len(sent))
	}
}

func frames2(f func(fr *http2.Framer)) []byte {
	var b bytes.Buffer
	f(http2.NewFramer(&b, nil))
	return b.Bytes()
}

// serverFrame is one frame of the server's bytes, whether an answer may come
// before it, not inside a header block, and whether it ends inside a frame.
type serverFrame struct {
	b       []byte
	between bool
	partial bool
}

// serverFrames splits b into frames by their headers; what is left past the
// last whole one comes as one more piece.
func serverFrames(b []byte) []serverFrame {
	var out []serverFrame
	inBlock := false
	for len(b) >= h2FrameHeader {
		n := h2FrameHeader + (int(b[0])<<16 | int(b[1])<<8 | int(b[2]))
		if n > len(b) {
			break
		}
		out = append(out, serverFrame{b: b[:n], between: !inBlock})
		switch b[3] {
		case h2Headers, h2PushPromise, h2Continuation:
			inBlock = b[4]&h2FlagEndHeaders == 0
		}
		b = b[n:]
	}
	if len(b) > 0 {
		out = append(out, serverFrame{b: b, between: !inBlock, partial: true})
	}
	return out
}

// unansweredPings walks the whole frames of b past from and returns the
// payloads of the PINGs among them that ask for an answer, and where the
// walk stopped.
func unansweredPings(b []byte, from int) ([][8]byte, int) {
	var out [][8]byte
	for len(b)-from >= h2FrameHeader {
		h := b[from:]
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		if len(h) < h2FrameHeader+n {
			break
		}
		if h[3] == h2Ping && h[4]&h2FlagAck == 0 && n == 8 {
			var p [8]byte
			copy(p[:], h[h2FrameHeader:])
			out = append(out, p)
		}
		from += h2FrameHeader + n
	}
	return out, from
}

// readAvailable reads what the governor passes on of what was fed so far.
func readAvailable(c *flowConn, buf []byte) ([]byte, error) {
	var got []byte
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return got, nil
			}
			return got, err
		}
	}
}

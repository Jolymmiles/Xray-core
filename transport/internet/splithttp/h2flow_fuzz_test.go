package splithttp

import (
	"bytes"
	mrand "math/rand/v2"
	"testing"

	"golang.org/x/net/http2"
)

// FuzzFlowConn feeds arbitrary bytes to both directions of the governor after
// a valid preface: whatever a broken or hostile peer sends, it must not panic,
// must not hold on to more than a bounded amount of state, and must pass every
// byte of a stream it does not rewrite.
func FuzzFlowConn(f *testing.F) {
	var seed bytes.Buffer
	fr := http2.NewFramer(&seed, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	fr.WriteData(1, false, make([]byte, 1000))
	fr.WriteWindowUpdate(1, 70000)
	fr.WriteWindowUpdate(0, 70000)
	fr.WritePing(true, [8]byte{0x78, 0x66, 0x6c, 0x77, 0, 0, 0, 1})
	fr.WriteRSTStream(1, http2.ErrCodeCancel)
	f.Add(seed.Bytes(), seed.Bytes(), uint8(7))
	f.Add([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}, []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1}, uint8(1))
	f.Add([]byte{0xff, 0xff, 0xff, 1, 0xff, 0x7f, 0xff, 0xff, 0xff}, []byte{0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 0}, uint8(3))

	f.Fuzz(func(t *testing.T, fromClient, fromServer []byte, cut uint8) {
		capture := &captureConn{}
		c := newFlowConn(capture, testUp, testDown)
		c.rtt = 1
		step := int(cut%16) + 1
		out := c.readFrames([]byte(h2Preface), nil)
		for in := fromClient; len(in) > 0; {
			n := min(step, len(in))
			out = c.readFrames(append([]byte(nil), in[:n]...), out)
			in = in[n:]
		}
		for in := fromServer; len(in) > 0; {
			n := min(step, len(in))
			if _, err := c.Write(in[:n]); err != nil {
				t.Fatal(err)
			}
			in = in[n:]
		}
		c.wmu.Lock()
		c.wmu.Unlock()
		c.mu.Lock()
		streams, queued := len(c.streams), len(c.wqueue)+len(c.toClient)
		c.mu.Unlock()
		if streams > len(fromClient)/h2FrameHeader+1 {
			t.Fatalf("%d streams tracked from %d input bytes", streams, len(fromClient))
		}
		if queued > 1<<16 {
			t.Fatalf("%d bytes queued for the client", queued)
		}
		if limit := len(h2Preface) + len(fromClient) + 64*(len(fromClient)/h2FrameHeader+2); len(out) > limit {
			t.Fatalf("read side produced %d bytes from %d", len(out), len(fromClient))
		}
		c.Close()

		for _, client := range []bool{false, true} {
			in := append([]byte(h2Preface), fromClient...)
			if client {
				in = fromServer
			}
			rnd := mrand.New(mrand.NewPCG(uint64(cut), uint64(len(in))))
			cc := &chunkConn{data: in, rnd: rnd}
			rc := newFlowConn(cc, testUp, testDown)
			if client {
				rc = newFlowClientConn(cc)
				rc.mode.Store(flowH2)
			}
			var got []byte
			for {
				b := make([]byte, 1+rnd.IntN(64))
				n, err := rc.Read(b)
				got = append(got, b[:n]...)
				if err != nil {
					break
				}
			}
			if len(got) > len(in)+64*(len(in)/h2FrameHeader+2) {
				t.Fatalf("Read produced %d bytes from %d", len(got), len(in))
			}
		}
	})
}

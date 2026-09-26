package splithttp

import (
	"bytes"
	mrand "math/rand/v2"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// chunkConn serves data in random pieces and swallows writes.
type chunkConn struct {
	net.Conn
	data []byte
	rnd  *mrand.Rand
}

func (c *chunkConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, net.ErrClosed
	}
	n := min(len(b), len(c.data), 1+c.rnd.IntN(3000))
	copy(b, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *chunkConn) SetDeadline(time.Time) error      { return nil }
func (c *chunkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chunkConn) SetWriteDeadline(time.Time) error { return nil }
func (c *chunkConn) Close() error                     { return nil }

func frameStream(clientSide bool) ([]byte, map[uint32][]byte) {
	var s bytes.Buffer
	if clientSide {
		s.WriteString(h2Preface)
	}
	fr := http2.NewFramer(&s, nil)
	fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	data := map[uint32][]byte{}
	for i := 0; i < 400; i++ {
		id := uint32(1 + 2*(i%7))
		if clientSide && i < 7 {
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte{0x82}, EndHeaders: true})
		}
		p := make([]byte, mrand.IntN(16384))
		for j := range p {
			p[j] = byte(i*31 + j)
		}
		fr.WriteData(id, false, p)
		data[id] = append(data[id], p...)
		if i%5 == 0 {
			fr.WriteWindowUpdate(0, 1000)
			fr.WriteWindowUpdate(id, 70000)
		}
	}
	return s.Bytes(), data
}

// TestFlowReadChunked reads frames through the governor in random pieces
// into buffers of random size: what it holds back of a split frame makes its
// output longer than a read at times, and none of it may be lost or reordered.
func TestFlowReadChunked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		client   bool
		governed bool
	}{
		{"server passthrough", false, false},
		{"server governed", false, true},
		{"client passthrough", true, false},
		{"client governed", true, true},
	} {
		in, want := frameStream(!tc.client)
		for round := 0; round < 100; round++ {
			rnd := mrand.New(mrand.NewPCG(uint64(round), 7))
			cc := &chunkConn{data: append([]byte(nil), in...), rnd: rnd}
			var c *flowConn
			switch {
			case tc.client:
				c = newFlowClientConn(cc)
				c.mode.Store(flowH2)
				if !tc.governed {
					c.down = flowLimit{}
				}
			case tc.governed:
				c = newFlowConn(cc, flowDefault, flowDefault)
			default:
				c = newFlowConn(cc, flowLimit{}, flowLimit{})
			}
			var got []byte
			for {
				b := make([]byte, 1+rnd.IntN(5000))
				n, err := c.Read(b)
				got = append(got, b[:n]...)
				if err != nil {
					break
				}
			}
			if !tc.governed {
				if !bytes.Equal(got, in) {
					t.Fatalf("%s round %d: output differs from input", tc.name, round)
				}
				continue
			}
			if !tc.client {
				got = got[len(h2Preface):]
			}
			fr := http2.NewFramer(nil, bytes.NewReader(got))
			fr.SetMaxReadFrameSize(1 << 24)
			data := map[uint32][]byte{}
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					break
				}
				if d, ok := f.(*http2.DataFrame); ok {
					data[d.StreamID] = append(data[d.StreamID], d.Data()...)
				}
			}
			for id, w := range want {
				if !bytes.Equal(data[id], w) {
					t.Fatalf("%s round %d: stream %d data differs", tc.name, round, id)
				}
			}
		}
	}
}

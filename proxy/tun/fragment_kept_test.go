package tun

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// A TCP segment that is put together outside the buffers the link was read
// into is copied rather than kept: keeping it took the buffer the last piece
// was read into instead, and the connection read other bytes. Fragments are
// put together by the reassembly, a segment larger than a buffer is joined when
// its checksum is looked at.
func TestTCPSegmentPutTogetherWithSegments(t *testing.T) {
	for _, test := range []struct {
		name, src, dst string
		verify         bool
		size, fragment int
	}{
		{"fragments", "10.0.0.1:1234", "10.0.0.2:80", false, 5000, 1024},
		{"fragments over IPv6", "[fd00::1]:1234", "[fd00::2]:80", false, 5000, 1024},
		{"joined to verify", "10.0.0.1:1234", "10.0.0.2:80", true, 30000, 0},
		{"joined to verify over IPv6", "[fd00::1]:1234", "[fd00::2]:80", true, 30000, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			conns := make(chan accepted, 1)
			p, l := newPeer(t, test.src, test.dst)
			l.segments = true
			s := newTestStack(t, l, accept(conns))
			s.verify = test.verify
			p.connect(nil)
			a := take(t, conns)

			sent := make([]byte, test.size)
			rand.Read(sent)
			packet := summed(p.bytes(p.seq, tcpAck|tcpPsh, nil, sent))
			if test.fragment == 0 {
				l.in <- packet
			} else {
				for _, part := range split(packet, test.fragment, 1) {
					l.in <- part
				}
			}
			for r := p.receive(); r.ack != p.seq+uint32(len(sent)); r = p.receive() {
			}

			// what was acknowledged is queued: reading it does not wait, unless something is wrong
			received := make(chan []byte, 1)
			go func() {
				var b []byte
				for len(b) < len(sent) {
					mb, err := a.conn.(buf.Reader).ReadMultiBuffer()
					if err != nil {
						break
					}
					for _, part := range mb {
						b = append(b, part.Bytes()...)
					}
					buf.ReleaseMulti(mb)
				}
				received <- b
			}()
			select {
			case b := <-received:
				if !bytes.Equal(b, sent) {
					t.Fatalf("read %d bytes other than the %d that were sent", len(b), len(sent))
				}
			case <-time.After(5 * time.Second):
				t.Fatal("not all that was acknowledged could be read")
			}
		})
	}
}

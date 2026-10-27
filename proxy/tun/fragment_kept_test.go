package tun

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// A TCP segment that came in fragments is put together outside the buffers the
// link was read into, so it is copied rather than kept: keeping it took the
// buffer of the last fragment instead, and the connection read other bytes.
func TestTCPSegmentFromFragmentsWithSegments(t *testing.T) {
	for _, test := range []struct{ src, dst string }{
		{"10.0.0.1:1234", "10.0.0.2:80"},
		{"[fd00::1]:1234", "[fd00::2]:80"},
	} {
		conns := make(chan accepted, 1)
		p, l := newPeer(t, test.src, test.dst)
		l.segments = true
		newTestStack(t, l, accept(conns))
		p.connect(nil)
		a := take(t, conns)

		sent := make([]byte, 5000)
		rand.Read(sent)
		for _, part := range split(summed(p.bytes(p.seq, tcpAck|tcpPsh, nil, sent)), 1024, 1) {
			l.in <- part
		}
		for r := p.receive(); r.ack != p.seq+uint32(len(sent)); r = p.receive() {
		}
		var received []byte
		for len(received) < len(sent) {
			mb, err := a.conn.(buf.Reader).ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range mb {
				received = append(received, b.Bytes()...)
			}
			buf.ReleaseMulti(mb)
		}
		if !bytes.Equal(received, sent) {
			t.Fatal(test.src, ": read something else than what was sent in fragments")
		}
	}
}

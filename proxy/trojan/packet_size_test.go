package trojan_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/proxy/trojan"
)

// An older Xray Trojan reader ends the session on a payload above 8192 bytes,
// so the writer drops a larger datagram rather than send it, as the VLESS and
// VMess writers drop theirs. Every datagram up to 8192 bytes must go whole,
// whatever its address: the writer built each packet in a buffer of 8192
// bytes, so a long payload overflowed it with the header and ended the
// session.
func TestPacketWriterSendsWhatReadersTake(t *testing.T) {
	ip := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353)
	domain := net.UDPDestination(net.DomainAddress("resolver.example.com"), 53)
	type datagram struct {
		destination net.Destination
		payload     []byte
	}
	datagrams := []datagram{
		{ip, bytes.Repeat([]byte{1}, 100)},
		{domain, bytes.Repeat([]byte{2}, 8192)}, // the largest an older reader takes
		{ip, bytes.Repeat([]byte{3}, 8193)},
		{domain, bytes.Repeat([]byte{4}, 200)},
	}
	var stream bytes.Buffer
	writer := &PacketWriter{Writer: &stream, Target: ip}
	for _, d := range datagrams {
		b := buf.NewWithSize(int32(len(d.payload)))
		b.Write(d.payload)
		destination := d.destination
		b.UDP = &destination
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("writing %d bytes to %v: %v", len(d.payload), d.destination, err)
		}
	}

	reader := &PacketReader{Reader: &stream}
	for _, want := range []datagram{datagrams[0], datagrams[1], datagrams[3]} {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading the datagram of %d bytes: %v", len(want.payload), err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want.payload) || mb[0].UDP.String() != want.destination.String() {
			t.Fatalf("read %d bytes to %v, want %d to %v", mb.Len(), mb[0].UDP, len(want.payload), want.destination)
		}
		buf.ReleaseMulti(mb)
	}
	if _, err := reader.ReadMultiBuffer(); errors.Cause(err) != io.EOF {
		t.Fatalf("after the datagrams: %v, want io.EOF", err)
	}
}

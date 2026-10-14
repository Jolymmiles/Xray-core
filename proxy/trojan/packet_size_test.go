package trojan_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/proxy/trojan"
)

// trojanPacket frames payload as a datagram of a Trojan UDP request to
// 192.0.2.7:5353: its address, its 2-byte length, CRLF and the payload.
func trojanPacket(payload []byte) []byte {
	packet := []byte{0x01, 192, 0, 2, 7}
	packet = binary.BigEndian.AppendUint16(packet, 5353)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(payload)))
	packet = append(packet, '\r', '\n')
	return append(packet, payload...)
}

// readTrojanPackets reads every datagram of stream with a PacketReader, each
// of which must come alone and addressed to destination.
func readTrojanPackets(t *testing.T, stream io.Reader, destination net.Destination) [][]byte {
	t.Helper()
	reader := &PacketReader{Reader: stream}
	var got [][]byte
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			if errors.Cause(err) != io.EOF {
				t.Fatalf("after %d datagrams: %v", len(got), err)
			}
			return got
		}
		if len(mb) != 1 {
			t.Fatalf("read %d buffers holding %d bytes, want one datagram", len(mb), mb.Len())
		}
		if mb[0].UDP == nil || mb[0].UDP.Address.String() != destination.Address.String() || mb[0].UDP.Port != destination.Port {
			t.Fatalf("datagram %d is addressed to %v, want %v", len(got), mb[0].UDP, destination)
		}
		got = append(got, bytes.Clone(mb[0].Bytes()))
		buf.ReleaseMulti(mb)
	}
}

// A peer may send a datagram above buf.Size, which Xray's writer does not, and
// up to the 65535 bytes the length allows. The reader ended the session on a
// payload above 8192 bytes, losing every datagram after it; it must keep every
// datagram whole, one per read.
func TestPacketReaderKeepsLargeDatagramsWhole(t *testing.T) {
	datagrams := [][]byte{
		bytes.Repeat([]byte{1}, 9000),
		bytes.Repeat([]byte{2}, 100),
		bytes.Repeat([]byte{3}, buf.Size),
		bytes.Repeat([]byte{4}, buf.Size+1),
		bytes.Repeat([]byte{5}, 200),
		bytes.Repeat([]byte{6}, 65535), // the largest length
	}
	var stream bytes.Buffer
	for _, datagram := range datagrams {
		stream.Write(trojanPacket(datagram))
	}
	got := readTrojanPackets(t, &stream, net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 7}), 5353))
	if len(got) != len(datagrams) {
		t.Fatalf("read %d datagrams, want %d", len(got), len(datagrams))
	}
	for i := range datagrams {
		if !bytes.Equal(got[i], datagrams[i]) {
			t.Fatalf("datagram %d holds %d bytes other than the %d sent", i, len(got[i]), len(datagrams[i]))
		}
	}
}

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

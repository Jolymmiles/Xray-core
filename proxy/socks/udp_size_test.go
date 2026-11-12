package socks_test

import (
	"bytes"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/socks"
)

// A SOCKS UDP packet is the datagram behind a header of 10 bytes for an IPv4
// address, 22 for IPv6 and up to 262 for a domain. EncodeUDPPacket built it in
// a regular buffer and returned an empty one for a datagram that did not fit
// with its header, which the inbound and the outbound then sent as an empty
// datagram: from 8183 bytes to an IPv4 address. It must encode each datagram
// whole, as the readers hand it on whole.
func TestEncodeUDPPacketKeepsLargeDatagramsWhole(t *testing.T) {
	for _, address := range []net.Address{
		net.IPAddress([]byte{192, 0, 2, 1}),
		net.IPAddress(net.ParseIP("2001:db8::1")),
		net.DomainAddress("resolver.example.com"),
	} {
		for _, size := range []int{1, buf.Size - 22, buf.Size - 10, buf.Size - 9, buf.Size, 9000, 65535} {
			datagram := bytes.Repeat([]byte{byte(size)}, size)
			packet, err := EncodeUDPPacket(&protocol.RequestHeader{Address: address, Port: 53}, datagram)
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeUDPPacket(packet)
			if err != nil {
				t.Fatalf("decoding the packet of %d bytes to %v: %v", size, address, err)
			}
			if request.Address.String() != address.String() || !bytes.Equal(packet.Bytes(), datagram) {
				t.Fatalf("a datagram of %d bytes to %v came back as %d bytes to %v", size, address, packet.Len(), request.Address)
			}
			packet.Release()
		}
	}
}

// The SOCKS outbound sends each datagram whole, drops one that its socket
// refuses as too long and goes on; any other error still ends the session.
func TestUDPWriterSendsLargeDatagramsWhole(t *testing.T) {
	sink, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	conn, err := stdnet.DialUDP("udp", nil, sink.LocalAddr().(*stdnet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writer := &UDPWriter{Writer: conn, Request: &protocol.RequestHeader{Address: net.IPAddress([]byte{192, 0, 2, 1}), Port: 53}}
	sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, 9000), bytes.Repeat([]byte{3}, 65535), []byte("pong")}
	mb := make(buf.MultiBuffer, len(sent))
	for i, datagram := range sent {
		mb[i] = buf.NewWithSize(int32(len(datagram)))
		mb[i].Write(datagram)
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() = %v, want the datagram the socket refuses dropped", err)
	}
	received := make([]byte, 65536)
	for _, want := range [][]byte{sent[0], sent[1], sent[3]} {
		if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sink.ReadFrom(received)
		if err != nil {
			t.Fatalf("waiting for the datagram of %d bytes: %v", len(want), err)
		}
		if n != 10+len(want) || !bytes.Equal(received[10:n], want) {
			t.Fatalf("received a packet of %d bytes, want the datagram of %d behind its header", n, len(want))
		}
	}

	conn.Close()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping"))}); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("WriteMultiBuffer() = %v, want the error of the closed socket", err)
	}
}

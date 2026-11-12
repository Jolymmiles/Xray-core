package socks_test

import (
	"bytes"
	"encoding/binary"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/proxy/socks"
)

// The SOCKS outbound reads the replies of its SOCKS server from a UDP
// socket, which cut a packet longer than the 8192 bytes of a read without a
// sign, and the reader passed its start on as a whole datagram. It drops
// such a packet and returns the next.
func TestUDPReaderDropsPacketsLongerThanARead(t *testing.T) {
	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, err := stdnet.DialUDP("udp", nil, conn.LocalAddr().(*stdnet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// a SOCKS UDP packet from 192.0.2.1:53
	packet := func(payload []byte) []byte {
		header := []byte{0, 0, 0, 1, 192, 0, 2, 1}
		return append(binary.BigEndian.AppendUint16(header, 53), payload...)
	}
	sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, 9000), []byte("pong")}
	for _, payload := range sent {
		if _, err := server.Write(packet(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := &UDPReader{Reader: conn}
	for _, want := range [][]byte{sent[0], sent[2]} {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("reading %q: %v", want, err)
		}
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) {
			t.Fatalf("read a datagram of %d bytes, want %q", mb.Len(), want)
		}
		buf.ReleaseMulti(mb)
	}
}

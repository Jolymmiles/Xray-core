package socks_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	. "github.com/xtls/xray-core/proxy/socks"
)

// The UDP socket of an association reads up to 8192 bytes, buf.Size, of a
// datagram, and passed the start of a longer one on as a datagram of its own,
// which the outbound then sent as if whole. It drops such a datagram and
// returns the next.
func TestTempUDPConnDropsDatagramsLongerThanTheRead(t *testing.T) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, socket.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	tcpServer, tcpClient := net.Pipe()
	defer tcpClient.Close()
	conn := NewTempUDPConn(socket, tcpServer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	conn.SetTimeout(time.Minute)
	defer conn.Close()

	for _, datagram := range [][]byte{bytes.Repeat([]byte{1}, 9000), []byte("ping")} {
		if _, err := client.Write(datagram); err != nil {
			t.Fatal(err)
		}
	}
	if err := socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 8192)
	n, err := conn.Read(read)
	if err != nil {
		t.Fatal(err)
	}
	if string(read[:n]) != "ping" {
		t.Fatalf("Read() returned %d bytes, want the datagram after the one of 9000", n)
	}
}

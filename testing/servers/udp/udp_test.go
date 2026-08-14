package udp

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestServerCloseWhileHandlingPacket(t *testing.T) {
	server := &Server{MsgProcessor: func(message []byte) []byte { return message }}
	destination, err := server.Start()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: destination.Address.IP(), Port: int(destination.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("payload"))
	if _, err := connection.Read(response); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

package shadowsocks_test

import (
	"bytes"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/shadowsocks"
)

// The Shadowsocks outbound reads the replies of its server from a UDP
// socket, which cut a packet longer than the 8192 bytes of a read without a
// sign. The cut packet failed authentication, and the error ended the UDP
// session. The reader drops such a packet and returns the next.
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
	user := &protocol.MemoryUser{Account: toAccount(&Account{Password: "password", CipherType: CipherType_AES_128_GCM})}
	request := &protocol.RequestHeader{Version: Version, Command: protocol.RequestCommandUDP, Address: net.LocalHostIP, Port: 53, User: user}
	sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, 9000), []byte("pong")}
	for _, payload := range sent {
		packet, err := EncodeUDPPacket(request, payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = server.Write(packet.Bytes())
		packet.Release()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := &UDPReader{Reader: conn, User: user}
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

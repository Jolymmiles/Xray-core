package shadowsocks_test

import (
	"bytes"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/shadowsocks"
)

// The inbounds hand an outbound a UDP datagram whole, up to 65535 bytes, but
// the socket refuses a Shadowsocks packet longer than an IP packet holds with
// EMSGSIZE, which ended the UDP session. The writer drops that datagram and
// sends the rest of the MultiBuffer; any other error still ends the session.
func TestUDPWriterDropsDatagramsTheSocketRefusesAsTooLong(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	user := &protocol.MemoryUser{Account: toAccount(&Account{Password: "password", CipherType: CipherType_AES_128_GCM})}
	writer := &UDPWriter{Writer: conn, Request: &protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandUDP,
		Address: net.LocalHostIP,
		Port:    53,
		User:    user,
	}}
	payloads := [][]byte{bytes.Repeat([]byte{1}, 100), bytes.Repeat([]byte{2}, 65500), bytes.Repeat([]byte{3}, 200)}
	mb := make(buf.MultiBuffer, len(payloads))
	for i, payload := range payloads {
		mb[i] = buf.NewWithSize(int32(len(payload)))
		mb[i].Write(payload)
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() = %v, want the datagram the socket refuses dropped", err)
	}

	validator := new(Validator)
	validator.Add(user)
	received := make([]byte, 65536)
	for _, want := range [][]byte{payloads[0], payloads[2]} {
		if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sink.ReadFrom(received)
		if err != nil {
			t.Fatalf("waiting for the datagram of %d bytes: %v", len(want), err)
		}
		packet := buf.New()
		packet.Write(received[:n])
		_, payload, err := DecodeUDPPacket(validator, packet)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload.Bytes(), want) {
			t.Fatalf("received a datagram of %d bytes, want the one of %d", payload.Len(), len(want))
		}
		payload.Release()
	}

	conn.Close()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping"))}); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("WriteMultiBuffer() = %v, want the error of the closed socket", err)
	}
}

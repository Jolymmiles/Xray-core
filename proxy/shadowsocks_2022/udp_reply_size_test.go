package shadowsocks_2022

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// The outbounds hand the Shadowsocks 2022 server a UDP reply whole, up to
// 65535 bytes, but the socket back to the client refuses a packet longer than
// an IP packet holds with EMSGSIZE, which ended the reply loop and with it
// every later reply of the session. The loop drops that reply and sends the
// next, with and without an encoder.
func TestUDPReplyLoopDropsRepliesTheSocketRefusesAsTooLong(t *testing.T) {
	for name, encode := range map[string]func(net.Destination, []byte) ([]byte, error){
		"plain":   nil,
		"encoded": func(_ net.Destination, payload []byte) ([]byte, error) { return bytes.Clone(payload), nil },
	} {
		t.Run(name, func(t *testing.T) {
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

			s := &ServerUDPSession{}
			s.UpdateConn(conn)
			reader, writer := pipe.New(pipe.WithoutSizeLimit())
			long := buf.NewWithSize(65508)
			long.Extend(65508)
			replies := buf.MultiBuffer{buf.FromBytes([]byte("ping")), long, buf.FromBytes([]byte("pong"))}
			if err := writer.WriteMultiBuffer(replies); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			done := make(chan struct{})
			go func() {
				handleUDPResponse(s, &transport.Link{Reader: reader}, net.UDPDestination(net.LocalHostIP, 53), encode)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the reply loop did not end with its link")
			}

			received := make([]byte, 65536)
			for _, want := range []string{"ping", "pong"} {
				if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				n, _, err := sink.ReadFrom(received)
				if err != nil {
					t.Fatalf("waiting for %q: %v", want, err)
				}
				if string(received[:n]) != want {
					t.Fatalf("received a reply of %d bytes, want %q", n, want)
				}
			}
		})
	}
}

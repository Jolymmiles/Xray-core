package dispatcher_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	vlessencoding "github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessencoding "github.com/xtls/xray-core/proxy/vmess/encoding"
)

// longestTarget is a destination with the longest domain an address field
// holds, so that the framings that address each datagram spend the most on
// it. Sniffing with destOverride makes the sniffed server name the target.
var longestTarget = net.UDPDestination(net.DomainAddress(strings.Repeat("d", 255)), 443)

// The QUIC sniffer reads the datagrams of a UDP flow as the outbound sends
// them, and names no server once it meets one longer than
// quic.MaxProxiedDatagram. Freedom sends each datagram as it is; a proxy
// outbound frames each for its server, which hands it on. These tests pin the
// bound to the framings: datagrams of exactly that size, several in one
// MultiBuffer and addressed to longestTarget, come out of the reader of the
// matching server as the same datagrams, each whole in a buffer of its own. A
// framing that carries less fails here, and the bound must then follow it.
func TestProxyFramingsCarryTheLongestSniffedDatagramsWhole(t *testing.T) {
	framings := []struct {
		name      string
		roundTrip func(*testing.T, buf.MultiBuffer) [][]byte
	}{
		{"VLESS", vlessRoundTrip},
		{"XUDP in VLESS", xudpRoundTrip},
		{"Mux.Cool", muxCoolRoundTrip},
		{"VMess AES-128-GCM", vmessRoundTrip(protocol.SecurityType_AES128_GCM, false)},
		{"VMess AES-128-GCM, authenticated length", vmessRoundTrip(protocol.SecurityType_AES128_GCM, true)},
		{"VMess ChaCha20-Poly1305", vmessRoundTrip(protocol.SecurityType_CHACHA20_POLY1305, false)},
		{"VMess ChaCha20-Poly1305, authenticated length", vmessRoundTrip(protocol.SecurityType_CHACHA20_POLY1305, true)},
		{"Trojan", trojanRoundTrip},
		{"Shadowsocks AES-128-GCM", shadowsocksRoundTrip(shadowsocks.CipherType_AES_128_GCM)},
		{"Shadowsocks AES-256-GCM", shadowsocksRoundTrip(shadowsocks.CipherType_AES_256_GCM)},
		{"Shadowsocks ChaCha20-Poly1305", shadowsocksRoundTrip(shadowsocks.CipherType_CHACHA20_POLY1305)},
		{"Shadowsocks XChaCha20-Poly1305", shadowsocksRoundTrip(shadowsocks.CipherType_XCHACHA20_POLY1305)},
		{"Shadowsocks 2022 AES-128-GCM", shadowsocks2022RoundTrip(shadowsocks_2022.MethodAES128GCM)},
		{"Shadowsocks 2022 AES-256-GCM", shadowsocks2022RoundTrip(shadowsocks_2022.MethodAES256GCM)},
		{"Shadowsocks 2022 ChaCha20-Poly1305", shadowsocks2022RoundTrip(shadowsocks_2022.MethodChaCha20Poly1305)},
		{"SOCKS", socksRoundTrip},
	}
	for _, framing := range framings {
		t.Run(framing.name, func(t *testing.T) {
			datagrams := make([][]byte, 3)
			sent := make(buf.MultiBuffer, len(datagrams))
			for i := range datagrams {
				datagrams[i] = make([]byte, quic.MaxProxiedDatagram)
				common.Must2(rand.Read(datagrams[i]))
				sent[i] = buf.NewWithSize(int32(len(datagrams[i])))
				common.Must2(sent[i].Write(datagrams[i]))
				sent[i].UDP = &longestTarget
			}
			got := framing.roundTrip(t, sent)
			if len(got) != len(datagrams) {
				t.Fatalf("%d datagrams of %d bytes came out as %d buffers of %v bytes", len(datagrams), quic.MaxProxiedDatagram, len(got), lengths(got))
			}
			for i := range datagrams {
				if !bytes.Equal(got[i], datagrams[i]) {
					t.Fatalf("datagram %d came out as %d other bytes", i, len(got[i]))
				}
			}
		})
	}
}

// lengths returns the length of each datagram.
func lengths(datagrams [][]byte) []int {
	n := make([]int, len(datagrams))
	for i, datagram := range datagrams {
		n[i] = len(datagram)
	}
	return n
}

// readBuffers reads buffers from a server's reader until they hold size
// bytes, and returns each buffer's bytes.
func readBuffers(t *testing.T, reader buf.Reader, size int32) [][]byte {
	t.Helper()
	var got [][]byte
	for read := int32(0); read < size; {
		mb, err := reader.ReadMultiBuffer()
		for _, b := range mb {
			got = append(got, bytes.Clone(b.Bytes()))
			read += b.Len()
		}
		buf.ReleaseMulti(mb)
		if err != nil && read < size {
			t.Fatalf("after buffers of %v bytes: %v", lengths(got), err)
		}
	}
	return got
}

// write writes sent with the client's writer.
func write(t *testing.T, writer buf.Writer, sent buf.MultiBuffer) {
	t.Helper()
	if err := writer.WriteMultiBuffer(sent); err != nil {
		t.Fatalf("writing %d datagrams: %v", len(sent), err)
	}
}

// datagramConn records each Write as a datagram, as a UDP socket sends it.
type datagramConn struct {
	datagrams [][]byte
}

func (c *datagramConn) Write(b []byte) (int, error) {
	c.datagrams = append(c.datagrams, bytes.Clone(b))
	return len(b), nil
}

// receive returns datagram as the UDP hub of a server reads it, into a buffer
// of buf.Size bytes, which would cut a longer one
// (transport/internet/udp/hub.go). The buffer is released when the test ends.
func receive(t *testing.T, datagram []byte) *buf.Buffer {
	t.Helper()
	if len(datagram) > buf.Size {
		t.Fatalf("a datagram of %d bytes, which the server's UDP hub cuts to %d", len(datagram), buf.Size)
	}
	b := buf.New()
	t.Cleanup(b.Release)
	common.Must2(b.Write(datagram))
	return b
}

// The stream framings below write into a buf.MultiBufferContainer, from which
// the server's reader takes everything in one read, as ReadVReader takes
// several buffers of a TCP connection at once: a reader that reads on from
// what it holds (VMess) then meets several datagrams together.

// The VLESS outbound frames a UDP request's body with EncodeBody, and the
// inbound reads it with DecodeBody.
func vlessRoundTrip(t *testing.T, sent buf.MultiBuffer) [][]byte {
	request := &protocol.RequestHeader{Command: protocol.RequestCommandUDP, Address: longestTarget.Address, Port: longestTarget.Port}
	var stream buf.MultiBufferContainer
	defer stream.Close()
	size := sent.Len()
	write(t, vlessencoding.EncodeBody(buf.NewWriter(&stream), request, false, nil, true, context.Background(), nil, nil), sent)
	return readBuffers(t, vlessencoding.DecodeBody(&stream, request), size)
}

// readMuxPackets reads the packets of Mux.Cool frames as mux.ServerWorker
// does, until they hold size bytes.
func readMuxPackets(t *testing.T, stream io.Reader, size int32) [][]byte {
	t.Helper()
	var got [][]byte
	for read := int32(0); read < size; {
		var meta mux.FrameMetadata
		if err := meta.Unmarshal(stream, false); err != nil {
			t.Fatalf("after packets of %v bytes: %v", lengths(got), err)
		}
		if !meta.Option.Has(mux.OptionData) {
			continue
		}
		mb, err := mux.NewPacketReader(stream, &meta.Target).ReadMultiBuffer()
		if err != nil {
			t.Fatalf("after packets of %v bytes: %v", lengths(got), err)
		}
		for _, b := range mb {
			got = append(got, bytes.Clone(b.Bytes()))
			read += b.Len()
		}
		buf.ReleaseMulti(mb)
	}
	return got
}

// With XUDP, the VLESS outbound frames each datagram as a Mux.Cool packet,
// which the inbound's mux server reads.
func xudpRoundTrip(t *testing.T, sent buf.MultiBuffer) [][]byte {
	var stream buf.MultiBufferContainer
	defer stream.Close()
	size := sent.Len()
	write(t, xudp.NewPacketWriter(buf.NewWriter(&stream), longestTarget, [8]byte{1}), sent)
	return readMuxPackets(t, &stream, size)
}

// The mux client sends the datagrams of a UDP session as Mux.Cool packets.
func muxCoolRoundTrip(t *testing.T, sent buf.MultiBuffer) [][]byte {
	var stream buf.MultiBufferContainer
	defer stream.Close()
	size := sent.Len()
	write(t, mux.NewWriter(1, longestTarget, buf.NewWriter(&stream), protocol.TransferTypePacket, [8]byte{}, nil), sent)
	return readMuxPackets(t, &stream, size)
}

// The VMess outbound seals each datagram of a UDP request as a chunk, with
// chunk masking and padding for the AEAD securities, and the inbound opens
// it.
func vmessRoundTrip(security protocol.SecurityType, authenticatedLength bool) func(*testing.T, buf.MultiBuffer) [][]byte {
	return func(t *testing.T, sent buf.MultiBuffer) [][]byte {
		id := uuid.New()
		account, err := (&vmess.Account{Id: id.String()}).AsAccount()
		common.Must(err)
		user := &protocol.MemoryUser{Email: "proxied@example.com", Account: account}
		request := &protocol.RequestHeader{
			Version:  vmessencoding.Version,
			User:     user,
			Command:  protocol.RequestCommandUDP,
			Address:  longestTarget.Address,
			Port:     longestTarget.Port,
			Security: security,
			Option:   protocol.RequestOptionChunkStream,
		}
		request.Option.Set(protocol.RequestOptionChunkMasking)
		request.Option.Set(protocol.RequestOptionGlobalPadding)
		if authenticatedLength {
			request.Option.Set(protocol.RequestOptionAuthenticatedLength)
		}

		var stream buf.MultiBufferContainer
		defer stream.Close()
		size := sent.Len()
		client := vmessencoding.NewClientSession(context.Background(), 0)
		common.Must(client.EncodeRequestHeader(request, &stream))
		writer, err := client.EncodeRequestBody(request, &stream)
		common.Must(err)
		write(t, writer, sent)

		validator := vmess.NewTimedUserValidator()
		defer common.Close(validator)
		common.Must(validator.Add(user))
		history := vmessencoding.NewSessionHistory()
		defer common.Close(history)
		server := vmessencoding.NewServerSession(validator, history)
		received, err := server.DecodeRequestHeader(&stream, false)
		common.Must(err)
		reader, err := server.DecodeRequestBody(received, &stream)
		common.Must(err)
		return readBuffers(t, reader, size)
	}
}

// The Trojan outbound frames each datagram with its address and length.
func trojanRoundTrip(t *testing.T, sent buf.MultiBuffer) [][]byte {
	var stream buf.MultiBufferContainer
	defer stream.Close()
	size := sent.Len()
	write(t, &trojan.PacketWriter{Writer: &stream, Target: longestTarget}, sent)
	return readBuffers(t, &trojan.PacketReader{Reader: &stream}, size)
}

// The Shadowsocks outbound sends each datagram, with its address, in a UDP
// packet of its own, which the inbound decodes.
func shadowsocksRoundTrip(cipher shadowsocks.CipherType) func(*testing.T, buf.MultiBuffer) [][]byte {
	return func(t *testing.T, sent buf.MultiBuffer) [][]byte {
		account, err := (&shadowsocks.Account{Password: "proxied", CipherType: cipher}).AsAccount()
		common.Must(err)
		user := &protocol.MemoryUser{Account: account}
		request := &protocol.RequestHeader{
			Version: shadowsocks.Version,
			Command: protocol.RequestCommandUDP,
			Address: longestTarget.Address,
			Port:    longestTarget.Port,
			User:    user,
		}
		conn := new(datagramConn)
		write(t, &shadowsocks.UDPWriter{Writer: conn, Request: request}, sent)

		validator := new(shadowsocks.Validator)
		common.Must(validator.Add(user))
		got := make([][]byte, 0, len(conn.datagrams))
		for _, datagram := range conn.datagrams {
			// DecodeUDPPacket opens the packet in place and returns it.
			_, payload, err := shadowsocks.DecodeUDPPacket(validator, receive(t, datagram))
			if err != nil {
				t.Fatalf("after datagrams of %v bytes: %v", lengths(got), err)
			}
			got = append(got, bytes.Clone(payload.Bytes()))
		}
		return got
	}
}

// The Shadowsocks 2022 outbound sends each datagram, with its address, in a
// UDP packet of its own, which the inbound decodes. The client here has one
// key: each further key of a chain adds 16 bytes to a packet, so a chain of
// 24 keys or more no longer carries the bound to the longest domain.
func shadowsocks2022RoundTrip(methodName string) func(*testing.T, buf.MultiBuffer) [][]byte {
	return func(t *testing.T, sent buf.MultiBuffer) [][]byte {
		method, err := shadowsocks_2022.GetCipherMethod(methodName)
		common.Must(err)
		psk := make([]byte, method.KeySaltLength)
		common.Must2(rand.Read(psk))
		clientCodec, err := shadowsocks_2022.NewUDPPacketCodec(method, [][]byte{psk})
		common.Must(err)
		serverCodec, err := shadowsocks_2022.NewUDPServerCodec(method, psk, time.Minute)
		common.Must(err)
		session, err := clientCodec.NewClientSession()
		common.Must(err)
		conn := new(datagramConn)
		write(t, &shadowsocks_2022.UDPWriter{Writer: conn, Destination: longestTarget, Session: session}, sent)

		got := make([][]byte, 0, len(conn.datagrams))
		for _, datagram := range conn.datagrams {
			packet := receive(t, datagram)
			decoded, err := serverCodec.DecodePacket(packet.Bytes())
			if err != nil {
				t.Fatalf("after datagrams of %v bytes: %v", lengths(got), err)
			}
			got = append(got, bytes.Clone(decoded.Payload))
		}
		return got
	}
}

// The SOCKS outbound sends each datagram, with its address, in a UDP packet
// of its own to the server's UDP relay.
func socksRoundTrip(t *testing.T, sent buf.MultiBuffer) [][]byte {
	conn := new(datagramConn)
	request := &protocol.RequestHeader{Command: protocol.RequestCommandUDP, Address: longestTarget.Address, Port: longestTarget.Port}
	write(t, &socks.UDPWriter{Writer: conn, Request: request}, sent)

	got := make([][]byte, 0, len(conn.datagrams))
	for _, datagram := range conn.datagrams {
		packet := receive(t, datagram)
		if _, err := socks.DecodeUDPPacket(packet); err != nil {
			t.Fatalf("after datagrams of %v bytes: %v", lengths(got), err)
		}
		got = append(got, bytes.Clone(packet.Bytes()))
	}
	return got
}

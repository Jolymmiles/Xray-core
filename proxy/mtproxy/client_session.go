package mtproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const fakeTLSApplicationRecordLimit = 1425

type fakeTLSFallback struct {
	serverName  string
	clientHello []byte
}

func (e *fakeTLSFallback) Error() string { return "mtproxy: fake TLS camouflage fallback" }

type acceptedClient struct {
	state       *ObfuscatedState
	fingerprint SecretFingerprint
	reader      io.Reader
	fakeTLS     bool
}

var mtproxySessionID atomic.Uint64

func (h *Handler) processConnection(ctx context.Context, connection stat.Connection, dispatcher routing.Dispatcher) error {
	select {
	case h.handshakeSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("mtproxy: handshake capacity reached")
	}
	handshakeSlotHeld := true
	defer func() {
		if handshakeSlotHeld {
			<-h.handshakeSlots
		}
	}()
	accepted, err := h.acceptClient(connection)
	if err != nil {
		if fallback, ok := err.(*fakeTLSFallback); ok {
			return relayFakeTLSFallback(ctx, connection, dispatcher, fallback)
		}
		return err
	}
	// Authentication work is complete; release the scarce pre-auth slot before
	// dialing or relaying long-lived traffic.
	<-h.handshakeSlots
	handshakeSlotHeld = false

	sessionID := mtproxySessionID.Add(1)
	unregister, ok := h.secrets.RegisterSession(accepted.fingerprint, sessionID, func() { _ = connection.Close() })
	if !ok {
		return fmt.Errorf("mtproxy: client secret was revoked during handshake")
	}
	defer unregister()

	middleClient, err := h.middle.OpenClient(ctx, accepted.state.DCID, func() { _ = connection.Close() })
	if err != nil {
		return err
	}
	defer middleClient.Close()

	remoteIP, remotePort := endpointFromNetAddr(connection.RemoteAddr())
	localIP, localPort := endpointFromNetAddr(connection.LocalAddr())
	results := make(chan error, 2)
	go func() {
		results <- h.relayClientToMiddle(accepted, middleClient, remoteIP, remotePort, localIP, localPort)
	}()
	go func() {
		results <- h.relayMiddleToClient(connection, accepted, middleClient)
	}()
	firstError := <-results
	_ = connection.Close()
	middleClient.Close()
	secondError := <-results
	if firstError != nil {
		return firstError
	}
	return secondError
}

func (h *Handler) acceptClient(connection net.Conn) (*acceptedClient, error) {
	var prefix [5]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return nil, err
	}
	if prefix[0] == 0x16 && h.fakeTLS != nil {
		recordLength := int(binary.BigEndian.Uint16(prefix[3:5]))
		if recordLength <= 0 || recordLength+5 > fakeTLSMaxClientHello {
			return nil, ErrInvalidFakeTLS
		}
		hello := make([]byte, recordLength+5)
		copy(hello, prefix[:])
		if _, err := io.ReadFull(connection, hello[5:]); err != nil {
			return nil, err
		}
		auth, err := h.fakeTLS.Authenticate(hello)
		if err != nil {
			if serverName, allowed := FakeTLSFallbackServerName(hello, h.config.FakeTls.Domains); allowed {
				return nil, &fakeTLSFallback{serverName: serverName, clientHello: hello}
			}
			return nil, err
		}
		response, err := BuildFakeTLSServerHello(auth, rand.Reader, int(h.config.FakeTls.ServerHelloPayloadSize))
		if err != nil {
			return nil, err
		}
		if err := writeFull(connection, response); err != nil {
			return nil, err
		}
		if err := ConsumeFakeTLSChangeCipherSpec(connection); err != nil {
			return nil, err
		}
		recordReader := NewFakeTLSRecordReader(connection, fakeTLSMaxRecordPayload)
		var header [obfuscatedHeaderSize]byte
		if _, err := io.ReadFull(recordReader, header[:]); err != nil {
			return nil, err
		}
		state, err := auth.AcceptInnerHeader(header)
		if err != nil {
			return nil, err
		}
		return &acceptedClient{state: state, fingerprint: auth.Fingerprint, reader: &decryptingReader{reader: recordReader, state: state}, fakeTLS: true}, nil
	}
	if h.config.FakeTls != nil && h.config.FakeTls.Only {
		return nil, ErrInvalidFakeTLS
	}
	var header [obfuscatedHeaderSize]byte
	copy(header[:5], prefix[:])
	if _, err := io.ReadFull(connection, header[5:]); err != nil {
		return nil, err
	}
	for _, candidate := range h.secrets.candidates() {
		state, err := AcceptObfuscatedHeader(header, [][16]byte{candidate.secret})
		if err == nil {
			return &acceptedClient{state: state, fingerprint: candidate.fingerprint, reader: &decryptingReader{reader: connection, state: state}}, nil
		}
	}
	return nil, errInvalidObfuscated
}

func relayFakeTLSFallback(ctx context.Context, connection net.Conn, dispatcher routing.Dispatcher, fallback *fakeTLSFallback) error {
	if dispatcher == nil || fallback == nil || fallback.serverName == "" {
		return ErrInvalidFakeTLS
	}
	destination := corenet.TCPDestination(corenet.DomainAddress(fallback.serverName), 443)
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return err
	}
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(fallback.clientHello)}); err != nil {
		return err
	}
	return task.Run(ctx,
		func() error { return buf.Copy(buf.NewReader(connection), link.Writer) },
		func() error { return buf.Copy(link.Reader, buf.NewWriter(connection)) },
	)
}

type decryptingReader struct {
	reader io.Reader
	state  *ObfuscatedState
}

func (r *decryptingReader) Read(payload []byte) (int, error) {
	read, err := r.reader.Read(payload)
	if read > 0 {
		r.state.Decrypt(payload[:read])
	}
	return read, err
}

func (h *Handler) relayClientToMiddle(client *acceptedClient, middle *MiddleClient, remoteIP [16]byte, remotePort uint16, localIP [16]byte, localPort uint16) error {
	for {
		header, err := ReadFrameHeader(client.reader, client.state.Mode, int(h.config.MaxPacketSize))
		if err != nil {
			return err
		}
		wire := make([]byte, header.WireLength)
		if _, err := io.ReadFull(client.reader, wire); err != nil {
			return err
		}
		flags := uint32(0)
		if header.QuickAck {
			flags = 1 << 31
		}
		request := ProxyRequest{Flags: flags, RemoteIP: remoteIP, RemotePort: remotePort, LocalIP: localIP, LocalPort: localPort, Payload: wire[:header.PayloadLength]}
		if len(h.config.Upstream.ProxyTag) == 16 {
			var tag [16]byte
			copy(tag[:], h.config.Upstream.ProxyTag)
			request.ProxyTag = &tag
		}
		if err := middle.Send(request); err != nil {
			return err
		}
	}
}

func (h *Handler) relayMiddleToClient(connection net.Conn, client *acceptedClient, middle *MiddleClient) error {
	for delivery := range middle.Deliveries() {
		if delivery.Kind == MiddleDeliveryAck {
			ack := []byte{0xdd, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(ack[1:], delivery.Confirm)
			if err := writeClientCiphertext(connection, client, ack); err != nil {
				return err
			}
			continue
		}
		padding := 0
		if client.state.Mode == FrameModePaddedIntermediate {
			var randomByte [1]byte
			if _, err := io.ReadFull(rand.Reader, randomByte[:]); err != nil {
				return err
			}
			padding = int(randomByte[0] & 3)
		}
		header, headerLength, err := EncodeFrameHeader(client.state.Mode, len(delivery.Payload), padding, false)
		if err != nil {
			return err
		}
		frame := make([]byte, headerLength+len(delivery.Payload)+padding)
		copy(frame, header[:headerLength])
		copy(frame[headerLength:], delivery.Payload)
		if padding > 0 {
			if _, err := io.ReadFull(rand.Reader, frame[len(frame)-padding:]); err != nil {
				return err
			}
		}
		if err := writeClientCiphertext(connection, client, frame); err != nil {
			return err
		}
	}
	return nil
}

func writeClientCiphertext(connection net.Conn, client *acceptedClient, plaintext []byte) error {
	client.state.Encrypt(plaintext)
	if client.fakeTLS {
		return WriteFakeTLSApplicationData(connection, plaintext, fakeTLSApplicationRecordLimit)
	}
	return writeFull(connection, plaintext)
}

func endpointFromNetAddr(address net.Addr) ([16]byte, uint16) {
	var result [16]byte
	parsed, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return result, 0
	}
	if parsed.Addr().Is4() {
		result[10], result[11] = 0xff, 0xff
		ipv4 := parsed.Addr().As4()
		copy(result[12:], ipv4[:])
	} else {
		ipv6 := parsed.Addr().As16()
		copy(result[:], ipv6[:])
	}
	return result, parsed.Port()
}

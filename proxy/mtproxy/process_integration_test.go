//go:build integration

package mtproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
)

func TestMTProxyProcessPaddedRoundTrip(t *testing.T) {
	middleListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer middleListener.Close()
	upstreamSecret := bytes.Repeat([]byte{0x71}, 32)
	middleDone := make(chan error, 1)
	go func() { middleDone <- serveProcessMiddleOnce(middleListener, upstreamSecret) }()

	directory := t.TempDir()
	upstreamSecretPath := filepath.Join(directory, "proxy-secret")
	upstreamConfigPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(upstreamSecretPath, upstreamSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	middlePort := middleListener.Addr().(*net.TCPAddr).Port
	configText := []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", middlePort))
	if err := os.WriteFile(upstreamConfigPath, configText, 0o600); err != nil {
		t.Fatal(err)
	}
	clientSecret := testSecret(0x32)
	handler, err := New(context.Background(), &Config{
		Users:      []*protocol.User{{Email: "process@example", Account: serial.ToTypedMessage(&Account{Secret: clientSecret[:]})}},
		Upstream:   &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: upstreamSecretPath, ConfigFile: upstreamConfigPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 4},
		MaxSecrets: 16, MaxPacketSize: 1 << 20, HandshakeConcurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	clientConn, inboundConn := net.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- handler.Process(context.Background(), corenet.Network_TCP, inboundConn, nil) }()

	wireHeader, clientEncrypt, clientDecrypt := buildClientHeader(t, clientSecret, FrameModePaddedIntermediate, 2)
	if err := writeFull(clientConn, wireHeader[:]); err != nil {
		t.Fatal(err)
	}
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	frameHeader, frameHeaderLength, _ := EncodeFrameHeader(FrameModePaddedIntermediate, len(payload), 2, false)
	request := append([]byte(nil), frameHeader[:frameHeaderLength]...)
	request = append(request, payload...)
	request = append(request, 0xaa, 0xbb)
	clientEncrypt.XORKeyStream(request, request)
	if err := writeFull(clientConn, request); err != nil {
		t.Fatal(err)
	}

	decrypted := &cipher.StreamReader{S: clientDecrypt, R: clientConn}
	responseHeader, err := ReadFrameHeader(decrypted, FrameModePaddedIntermediate, 1<<20)
	if err != nil {
		select {
		case processErr := <-processDone:
			t.Fatalf("read response header: %v; Process: %v", err, processErr)
		default:
			t.Fatalf("read response header: %v", err)
		}
	}
	responseWire := make([]byte, responseHeader.WireLength)
	if _, err := io.ReadFull(decrypted, responseWire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseWire[:responseHeader.PayloadLength], payload) {
		t.Fatalf("response payload = %v, want %v", responseWire[:responseHeader.PayloadLength], payload)
	}
	if err := handler.RemoveUser(context.Background(), "process@example"); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var revokedByte [1]byte
	if _, err := clientConn.Read(revokedByte[:]); err == nil {
		t.Fatal("revoked client connection remained readable")
	}
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler Process did not stop after hard revoke")
	}
	if err := <-middleDone; err != nil {
		t.Fatal(err)
	}
}

func TestMTProxyProcessUsesReloadedUpstream(t *testing.T) {
	firstListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer firstListener.Close()
	secondListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secondListener.Close()
	firstSecret := bytes.Repeat([]byte{0x75}, 32)
	secondSecret := bytes.Repeat([]byte{0x76}, 32)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- serveProcessMiddleOnce(firstListener, firstSecret) }()
	go func() { secondDone <- serveProcessMiddleOnce(secondListener, secondSecret) }()

	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	configPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(secretPath, firstSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	firstPort := firstListener.Addr().(*net.TCPAddr).Port
	firstConfig := []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", firstPort))
	if err := os.WriteFile(configPath, firstConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	clientSecret := testSecret(0x72)
	handler, err := New(context.Background(), &Config{
		Users:      []*protocol.User{{Email: "reload@example", Account: serial.ToTypedMessage(&Account{Secret: clientSecret[:]})}},
		Upstream:   &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: secretPath, ConfigFile: configPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 4},
		MaxSecrets: 16, MaxPacketSize: 1 << 20, HandshakeConcurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	runPaddedProcessClient(t, handler, clientSecret, []byte{5, 5, 5, 5})
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	handler.middle.sessionsMu.Lock()
	firstSession := handler.middle.sessions[0]
	handler.middle.sessionsMu.Unlock()
	select {
	case <-firstSession.done:
	case <-time.After(2 * time.Second):
		t.Fatal("old upstream session did not close")
	}

	secondPort := secondListener.Addr().(*net.TCPAddr).Port
	secondConfig := []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", secondPort))
	reloaded, err := newUpstreamData(secondSecret, secondConfig, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler.upstream.Store(reloaded)
	runPaddedProcessClient(t, handler, clientSecret, []byte{6, 6, 6, 6})
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestMTProxyProcessReconnectsMiddleSession(t *testing.T) {
	middleListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer middleListener.Close()
	upstreamSecret := bytes.Repeat([]byte{0x74}, 32)
	middleDone := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			if err := serveProcessMiddleOnce(middleListener, upstreamSecret); err != nil {
				middleDone <- err
				return
			}
		}
		middleDone <- nil
	}()

	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	configPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(secretPath, upstreamSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	port := middleListener.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSecret := testSecret(0x62)
	handler, err := New(context.Background(), &Config{
		Users:      []*protocol.User{{Email: "reconnect@example", Account: serial.ToTypedMessage(&Account{Secret: clientSecret[:]})}},
		Upstream:   &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: secretPath, ConfigFile: configPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 4},
		MaxSecrets: 16, MaxPacketSize: 1 << 20, HandshakeConcurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	runPaddedProcessClient(t, handler, clientSecret, []byte{3, 3, 3, 3})
	handler.middle.sessionsMu.Lock()
	firstSession := handler.middle.sessions[0]
	handler.middle.sessionsMu.Unlock()
	select {
	case <-firstSession.done:
	case <-time.After(2 * time.Second):
		t.Fatal("first physical Middle-End session did not close")
	}
	runPaddedProcessClient(t, handler, clientSecret, []byte{4, 4, 4, 4})
	if err := <-middleDone; err != nil {
		t.Fatal(err)
	}
	handler.middle.sessionsMu.Lock()
	activeSessions := len(handler.middle.sessions)
	handler.middle.sessionsMu.Unlock()
	if activeSessions != 1 {
		t.Fatalf("tracked active Middle-End sessions = %d, want 1", activeSessions)
	}
}

func TestMTProxyProcessMultipleClientsShareMiddleSession(t *testing.T) {
	middleListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer middleListener.Close()
	upstreamSecret := bytes.Repeat([]byte{0x73}, 32)
	middleDone := make(chan error, 1)
	go func() { middleDone <- serveProcessMiddleClients(middleListener, upstreamSecret, 2) }()

	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	configPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(secretPath, upstreamSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	port := middleListener.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSecret := testSecret(0x52)
	handler, err := New(context.Background(), &Config{
		Users:      []*protocol.User{{Email: "shared@example", Account: serial.ToTypedMessage(&Account{Secret: clientSecret[:]})}},
		Upstream:   &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: secretPath, ConfigFile: configPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 4},
		MaxSecrets: 16, MaxPacketSize: 1 << 20, HandshakeConcurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	runPaddedProcessClient(t, handler, clientSecret, []byte{1, 1, 1, 1})
	runPaddedProcessClient(t, handler, clientSecret, []byte{2, 2, 2, 2})
	if err := <-middleDone; err != nil {
		t.Fatal(err)
	}
	handler.middle.sessionsMu.Lock()
	physicalSessions := len(handler.middle.sessions)
	handler.middle.sessionsMu.Unlock()
	if physicalSessions != 1 {
		t.Fatalf("physical Middle-End sessions = %d, want 1", physicalSessions)
	}
}

func runPaddedProcessClient(t *testing.T, handler *Handler, secret [16]byte, payload []byte) {
	t.Helper()
	clientConn, inboundConn := net.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- handler.Process(context.Background(), corenet.Network_TCP, inboundConn, nil) }()
	wireHeader, clientEncrypt, clientDecrypt := buildClientHeader(t, secret, FrameModePaddedIntermediate, 2)
	if err := writeFull(clientConn, wireHeader[:]); err != nil {
		t.Fatal(err)
	}
	frameHeader, frameHeaderLength, _ := EncodeFrameHeader(FrameModePaddedIntermediate, len(payload), 0, false)
	request := append([]byte(nil), frameHeader[:frameHeaderLength]...)
	request = append(request, payload...)
	clientEncrypt.XORKeyStream(request, request)
	if err := writeFull(clientConn, request); err != nil {
		t.Fatal(err)
	}
	decrypted := &cipher.StreamReader{S: clientDecrypt, R: clientConn}
	responseHeader, err := ReadFrameHeader(decrypted, FrameModePaddedIntermediate, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, responseHeader.WireLength)
	if _, err := io.ReadFull(decrypted, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:responseHeader.PayloadLength], payload) {
		t.Fatalf("response = %v, want %v", response[:responseHeader.PayloadLength], payload)
	}
	_ = clientConn.Close()
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		t.Fatal("shared client Process did not stop")
	}
}

func TestMTProxyProcessFakeTLSRoundTrip(t *testing.T) {
	middleListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer middleListener.Close()
	upstreamSecret := bytes.Repeat([]byte{0x72}, 32)
	middleDone := make(chan error, 1)
	go func() { middleDone <- serveProcessMiddleOnce(middleListener, upstreamSecret) }()

	directory := t.TempDir()
	upstreamSecretPath := filepath.Join(directory, "proxy-secret")
	upstreamConfigPath := filepath.Join(directory, "proxy-multi.conf")
	if err := os.WriteFile(upstreamSecretPath, upstreamSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	middlePort := middleListener.Addr().(*net.TCPAddr).Port
	configText := []byte(fmt.Sprintf("proxy_for 2 127.0.0.1:%d;\ndefault 2;\n", middlePort))
	if err := os.WriteFile(upstreamConfigPath, configText, 0o600); err != nil {
		t.Fatal(err)
	}
	clientSecret := testSecret(0x42)
	handler, err := New(context.Background(), &Config{
		Users:      []*protocol.User{{Email: "fake@example", Account: serial.ToTypedMessage(&Account{Secret: clientSecret[:]})}},
		Upstream:   &UpstreamConfig{Source: UpstreamSource_UPSTREAM_SOURCE_FILES, SecretFile: upstreamSecretPath, ConfigFile: upstreamConfigPath, MaxSessionsPerDc: 2, MaxClientsPerSession: 16, DeliveryQueueDepth: 4},
		FakeTls:    &FakeTLSConfig{Enabled: true, Only: true, Domains: []string{"cover.example"}, ReplayCacheCapacity: 16, ServerHelloPayloadSize: 128},
		MaxSecrets: 16, MaxPacketSize: 1 << 20, HandshakeConcurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	clientConn, inboundConn := net.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- handler.Process(context.Background(), corenet.Network_TCP, inboundConn, nil) }()
	hello := buildTestClientHello(t, clientSecret, "cover.example", time.Now().Unix())
	hello = fragmentClientHello(hello, []int{3, 1, 7, 11, 23})
	if err := writeFull(clientConn, hello); err != nil {
		t.Fatal(err)
	}
	if err := consumeFakeTLSServerResponse(clientConn); err != nil {
		t.Fatal(err)
	}
	if err := writeFull(clientConn, []byte{0x14, 0x03, 0x03, 0, 1, 1}); err != nil {
		t.Fatal(err)
	}

	wireHeader, clientEncrypt, clientDecrypt := buildClientHeader(t, clientSecret, FrameModePaddedIntermediate, 2)
	payload := []byte{11, 12, 13, 14, 15, 16, 17, 18}
	frameHeader, frameHeaderLength, _ := EncodeFrameHeader(FrameModePaddedIntermediate, len(payload), 1, false)
	request := append([]byte(nil), frameHeader[:frameHeaderLength]...)
	request = append(request, payload...)
	request = append(request, 0xcc)
	clientEncrypt.XORKeyStream(request, request)
	firstApplicationData := append(wireHeader[:], request...)
	if err := WriteFakeTLSApplicationData(clientConn, firstApplicationData, 64); err != nil {
		t.Fatal(err)
	}

	recordReader := NewFakeTLSRecordReader(clientConn, fakeTLSMaxRecordPayload)
	decrypted := &cipher.StreamReader{S: clientDecrypt, R: recordReader}
	responseHeader, err := ReadFrameHeader(decrypted, FrameModePaddedIntermediate, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	responseWire := make([]byte, responseHeader.WireLength)
	if _, err := io.ReadFull(decrypted, responseWire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseWire[:responseHeader.PayloadLength], payload) {
		t.Fatalf("Fake TLS response payload = %v, want %v", responseWire[:responseHeader.PayloadLength], payload)
	}
	_ = clientConn.Close()
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Fake TLS handler Process did not stop")
	}
	if err := <-middleDone; err != nil {
		t.Fatal(err)
	}
}

func consumeFakeTLSServerResponse(reader io.Reader) error {
	var handshakeHeader [5]byte
	if _, err := io.ReadFull(reader, handshakeHeader[:]); err != nil {
		return err
	}
	if handshakeHeader[0] != 0x16 {
		return fmt.Errorf("unexpected server handshake record type %x", handshakeHeader[0])
	}
	if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint16(handshakeHeader[3:5]))); err != nil {
		return err
	}
	var ccs [6]byte
	if _, err := io.ReadFull(reader, ccs[:]); err != nil {
		return err
	}
	if !bytes.Equal(ccs[:], []byte{0x14, 0x03, 0x03, 0, 1, 1}) {
		return fmt.Errorf("unexpected server ChangeCipherSpec %x", ccs)
	}
	var applicationHeader [5]byte
	if _, err := io.ReadFull(reader, applicationHeader[:]); err != nil {
		return err
	}
	if applicationHeader[0] != 0x17 {
		return fmt.Errorf("unexpected server application record type %x", applicationHeader[0])
	}
	_, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint16(applicationHeader[3:5])))
	return err
}

func serveProcessMiddleOnce(listener net.Listener, secret []byte) error {
	return serveProcessMiddleClients(listener, secret, 1)
}

func serveProcessMiddleClients(listener net.Listener, secret []byte, clientCount int) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	wire, err := handshakeProcessMiddle(connection, secret)
	if err != nil {
		return err
	}

	for clientIndex := 0; clientIndex < clientCount; clientIndex++ {
		requestBytes, err := wire.readMessage()
		if err != nil {
			return err
		}
		request, err := DecodeProxyRequest(requestBytes, 1<<20)
		if err != nil {
			return err
		}
		if request.Flags != 0x28021000 {
			return fmt.Errorf("unexpected padded transport flags %#x", request.Flags)
		}
		if err := wire.writeMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: request.ConnectionID, Payload: request.Payload})); err != nil {
			return err
		}
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		closeBytes, err := wire.readMessage()
		if err != nil {
			return err
		}
		_ = connection.SetReadDeadline(time.Time{})
		message, err := DecodeMiddleMessage(closeBytes, 1024)
		if err != nil {
			return err
		}
		if closeMessage, ok := message.(CloseConnection); !ok || closeMessage.ConnectionID != request.ConnectionID {
			return fmt.Errorf("unexpected logical close %#v", message)
		}
	}
	return nil
}

// handshakeProcessMiddle runs the peer side of the Middle-End handshake for
// both in-process and executable fixtures. The caller owns the connection.
func handshakeProcessMiddle(connection net.Conn, secret []byte) (*middleWire, error) {
	nonceFrame, err := ReadMiddleRPCFrame(connection, 512)
	if err != nil {
		return nil, err
	}
	clientNonce, err := DecodeMiddleNonce(nonceFrame.Payload)
	if err != nil {
		return nil, err
	}
	serverNonce := clientNonce
	for i := range serverNonce.Nonce {
		serverNonce.Nonce[i] ^= 0x5a
	}
	response, err := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(serverNonce))
	if err != nil {
		return nil, err
	}
	if err := writeFull(connection, response); err != nil {
		return nil, err
	}
	serverEndpoint, clientEndpoint, err := connectionEndpoints(connection)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveMiddleKeyData(false, secret, serverNonce.Nonce, clientNonce.Nonce, clientNonce.Timestamp, MiddleEndpoints{Server: serverEndpoint, Client: clientEndpoint})
	if err != nil {
		return nil, err
	}
	cbc, err := NewMiddleCBC(keys)
	if err != nil {
		return nil, err
	}
	wire := &middleWire{connection: connection, crypto: cbc, maxPayload: 1 << 20, writeSequence: -1, readSequence: -1}
	handshake, err := wire.readMessage()
	if err != nil {
		return nil, err
	}
	if err := validateHandshake(handshake); err != nil {
		return nil, err
	}
	if err := wire.writeMessage(handshake); err != nil {
		return nil, err
	}
	wire.crcTable = crc32.MakeTable(crc32.Castagnoli)
	return wire, nil
}

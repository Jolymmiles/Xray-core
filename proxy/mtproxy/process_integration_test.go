//go:build integration

package mtproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"fmt"
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
		t.Fatal(err)
	}
	responseWire := make([]byte, responseHeader.WireLength)
	if _, err := io.ReadFull(decrypted, responseWire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseWire[:responseHeader.PayloadLength], payload) {
		t.Fatalf("response payload = %v, want %v", responseWire[:responseHeader.PayloadLength], payload)
	}
	_ = clientConn.Close()
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler Process did not stop after client close")
	}
	if err := <-middleDone; err != nil {
		t.Fatal(err)
	}
}

func serveProcessMiddleOnce(listener net.Listener, secret []byte) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	nonceFrame, err := ReadMiddleRPCFrame(connection, 512)
	if err != nil {
		return err
	}
	clientNonce, err := DecodeMiddleNonce(nonceFrame.Payload)
	if err != nil {
		return err
	}
	serverNonce := clientNonce
	for i := range serverNonce.Nonce {
		serverNonce.Nonce[i] ^= 0x5a
	}
	response, _ := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(serverNonce))
	if err := writeFull(connection, response); err != nil {
		return err
	}
	serverEndpoint, clientEndpoint, err := connectionEndpoints(connection)
	if err != nil {
		return err
	}
	keys, err := DeriveMiddleKeyData(false, secret, serverNonce.Nonce, clientNonce.Nonce, clientNonce.Timestamp, MiddleEndpoints{Server: serverEndpoint, Client: clientEndpoint})
	if err != nil {
		return err
	}
	cbc, _ := NewMiddleCBC(keys)
	wire := &middleWire{connection: connection, crypto: cbc, maxPayload: 1 << 20, writeSequence: -1, readSequence: -1}
	handshake, err := wire.readMessage()
	if err != nil {
		return err
	}
	if err := wire.writeMessage(handshake); err != nil {
		return err
	}
	requestBytes, err := wire.readMessage()
	if err != nil {
		return err
	}
	request, err := DecodeProxyRequest(requestBytes, 1<<20)
	if err != nil {
		return err
	}
	return wire.writeMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: request.ConnectionID, Payload: request.Payload}))
}

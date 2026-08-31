package mtproxy

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestDialMiddleWireHandshakeAndRPC(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	secret := bytes.Repeat([]byte{0x62}, 32)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		nonceFrame, err := ReadMiddleRPCFrame(connection, 512)
		if err != nil {
			serverDone <- err
			return
		}
		clientNoncePacket, err := DecodeMiddleNonce(nonceFrame.Payload)
		if err != nil {
			serverDone <- err
			return
		}
		serverNoncePacket := clientNoncePacket
		for i := range serverNoncePacket.Nonce {
			serverNoncePacket.Nonce[i] ^= 0xa5
		}
		response, _ := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(serverNoncePacket))
		if err := writeFull(connection, response); err != nil {
			serverDone <- err
			return
		}
		serverEndpoint, clientEndpoint, err := connectionEndpoints(connection)
		if err != nil {
			serverDone <- err
			return
		}
		keys, err := DeriveMiddleKeyData(false, secret, serverNoncePacket.Nonce, clientNoncePacket.Nonce, clientNoncePacket.Timestamp, MiddleEndpoints{Server: serverEndpoint, Client: clientEndpoint})
		if err != nil {
			serverDone <- err
			return
		}
		cbc, _ := NewMiddleCBC(keys)
		wire := &middleWire{connection: connection, crypto: cbc, maxPayload: 1024, writeSequence: -1, readSequence: -1}
		handshake, err := wire.readMessage()
		if err != nil {
			serverDone <- err
			return
		}
		if err := validateHandshake(handshake); err != nil {
			serverDone <- err
			return
		}
		if err := wire.writeMessage(handshake); err != nil {
			serverDone <- err
			return
		}
		request, err := wire.readMessage()
		if err != nil {
			serverDone <- err
			return
		}
		decoded, err := DecodeProxyRequest(request, 1024)
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- wire.writeMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: decoded.ConnectionID, Payload: decoded.Payload}))
	}()

	address := listener.Addr().(*net.TCPAddr)
	wire, err := dialMiddleWire(context.Background(), MiddleEndpoint{Host: "127.0.0.1", Port: uint16(address.Port)}, secret, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer wire.connection.Close()
	request, _ := EncodeProxyRequest(ProxyRequest{ConnectionID: 77, Payload: []byte{1, 2, 3, 4}})
	if err := wire.writeMessage(request); err != nil {
		t.Fatal(err)
	}
	answer, err := wire.readMessage()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMiddleMessage(answer, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.(ProxyAnswer).ConnectionID; got != 77 {
		t.Fatalf("answer connection ID = %d", got)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestMiddleEncryptedWireRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	secret := bytes.Repeat([]byte{0x51}, 32)
	var serverNonce, clientNonce [16]byte
	copy(serverNonce[:], bytes.Repeat([]byte{1}, 16))
	copy(clientNonce[:], bytes.Repeat([]byte{2}, 16))
	endpoints := MiddleEndpoints{Server: netip.MustParseAddrPort("149.154.167.40:443"), Client: netip.MustParseAddrPort("203.0.113.9:50000")}
	clientKeys, _ := DeriveMiddleKeyData(true, secret, serverNonce, clientNonce, 1234, endpoints)
	serverKeys, _ := DeriveMiddleKeyData(false, secret, serverNonce, clientNonce, 1234, endpoints)
	clientCBC, _ := NewMiddleCBC(clientKeys)
	serverCBC, _ := NewMiddleCBC(serverKeys)
	clientWire := &middleWire{connection: clientConn, crypto: clientCBC, maxPayload: 1024}
	serverWire := &middleWire{connection: serverConn, crypto: serverCBC, maxPayload: 1024}

	serverDone := make(chan error, 1)
	go func() {
		requestBytes, err := serverWire.readMessage()
		if err != nil {
			serverDone <- err
			return
		}
		request, err := DecodeProxyRequest(requestBytes, 1024)
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- serverWire.writeMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: request.ConnectionID, Payload: request.Payload}))
	}()

	request := ProxyRequest{ConnectionID: 42, Payload: []byte{1, 2, 3, 4}}
	encoded, _ := EncodeProxyRequest(request)
	if err := clientWire.writeMessage(encoded); err != nil {
		t.Fatal(err)
	}
	answerBytes, err := clientWire.readMessage()
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMiddleMessage(answerBytes, 1024)
	if err != nil {
		t.Fatal(err)
	}
	answer := message.(ProxyAnswer)
	if answer.ConnectionID != 42 || !bytes.Equal(answer.Payload, request.Payload) {
		t.Fatalf("answer = %+v", answer)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

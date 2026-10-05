package mtproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
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
		wire.crcTable = crc32.MakeTable(crc32.Castagnoli)
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

func TestMiddleManagerDoesNotRollBackUpstreamGeneration(t *testing.T) {
	oldConfig, _ := ParseProxyConfig(bytes.NewBufferString("proxy_for 1 127.0.0.1:1;\ndefault 1;\n"), 4, 4)
	newConfig, _ := ParseProxyConfig(bytes.NewBufferString("proxy_for 2 127.0.0.1:2;\ndefault 2;\n"), 4, 4)
	oldData := &UpstreamData{Config: oldConfig, LoadedAt: time.Unix(100, 0)}
	newData := &UpstreamData{Config: newConfig, LoadedAt: time.Unix(200, 0)}
	var pointer atomic.Pointer[UpstreamData]
	pointer.Store(oldData)
	manager, err := newMiddleManager(&UpstreamConfig{MaxSessionsPerDc: 2}, &pointer, 1024)
	if err != nil {
		t.Fatal(err)
	}
	newPool, err := manager.poolFor(newData)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := manager.poolFor(oldData)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack != newPool || manager.appliedUpstream != newData {
		t.Fatal("older upstream generation replaced the active pool")
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

func TestDialMiddleWireCancellationDuringEncryptedHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	secret := bytes.Repeat([]byte{0x62}, 32)
	ready := make(chan error, 1)
	release := make(chan struct{})
	defer close(release)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			ready <- err
			return
		}
		defer connection.Close()
		frame, err := ReadMiddleRPCFrame(connection, 512)
		if err != nil {
			ready <- err
			return
		}
		nonce, err := DecodeMiddleNonce(frame.Payload)
		if err != nil {
			ready <- err
			return
		}
		nonce.Nonce[0] ^= 0xa5
		response, err := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(nonce))
		if err != nil {
			ready <- err
			return
		}
		if err := writeFull(connection, response); err != nil {
			ready <- err
			return
		}
		var handshake [48]byte
		_, err = io.ReadFull(connection, handshake[:])
		ready <- err
		<-release
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		wire, err := dialMiddleWire(ctx, MiddleEndpoint{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, secret, 1024)
		if wire != nil {
			wire.connection.Close()
		}
		done <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not receive encrypted handshake")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled encrypted handshake remained blocked")
	}
}

type readDeadlineConn struct {
	net.Conn
	deadline          time.Time
	firstReadDeadline time.Time
	deadlineChanged   bool
	reads             int
}

func (c *readDeadlineConn) Read(payload []byte) (int, error) {
	if c.reads == 0 {
		c.firstReadDeadline = c.deadline
	} else if !c.firstReadDeadline.Equal(c.deadline) {
		c.deadlineChanged = true
	}
	c.reads++
	return c.Conn.Read(payload)
}

func (c *readDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.deadline = deadline
	return c.Conn.SetReadDeadline(deadline)
}

func TestMiddleWirePreservesHandshakeDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline := time.Now().Add(time.Second)
	connection := &readDeadlineConn{Conn: client}
	if err := connection.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	server.Close()
	wire := &middleWire{connection: connection, maxPayload: 1024, readSequence: -1, handshaking: true}
	if _, err := wire.readMessage(); err == nil {
		t.Fatal("closed peer accepted")
	}
	if !connection.deadline.Equal(deadline) {
		t.Fatalf("handshake deadline changed from %s to %s", deadline, connection.deadline)
	}
}

func TestMiddleRetirementKeepsNewerGeneration(t *testing.T) {
	oldData := &UpstreamData{LoadedAt: time.Unix(100, 0)}
	newData := &UpstreamData{LoadedAt: time.Unix(200, 0)}
	core, err := NewMiddleSession(1, 1, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	current := &networkMiddleSession{wire: &middleWire{connection: client}, core: core, upstream: newData, done: make(chan struct{})}
	manager := &middleManager{sessions: []*networkMiddleSession{current}}
	defer manager.Close()
	// A delayed retirement from an earlier poolFor call must not retire a new session.
	manager.retireIdleSessions(oldData)
	if _, err := core.OpenClient(nil); err != nil {
		t.Fatalf("old generation retirement closed newer session: %v", err)
	}
}

func TestMiddleManagerRejectsDialFromReplacedGeneration(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	secret := bytes.Repeat([]byte{0x62}, 32)
	rawConfig := []byte(fmt.Sprintf("proxy_for 1 127.0.0.1:%d;\ndefault 1;\n", listener.Addr().(*net.TCPAddr).Port))
	oldData, err := newUpstreamData(secret, rawConfig, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	newData, err := newUpstreamData(secret, rawConfig, time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	var upstream atomic.Pointer[UpstreamData]
	upstream.Store(oldData)
	manager, err := newMiddleManager(&UpstreamConfig{MaxSessionsPerDc: 2, MaxClientsPerSession: 2, DeliveryQueueDepth: 2}, &upstream, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ready := make(chan error, 1)
	reply := make(chan struct{})
	defer close(reply)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			ready <- err
			return
		}
		defer connection.Close()
		frame, err := ReadMiddleRPCFrame(connection, 512)
		if err != nil {
			ready <- err
			return
		}
		clientNonce, err := DecodeMiddleNonce(frame.Payload)
		if err != nil {
			ready <- err
			return
		}
		serverNonce := clientNonce
		serverNonce.Nonce[0] ^= 0xa5
		response, _ := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(serverNonce))
		if err := writeFull(connection, response); err != nil {
			ready <- err
			return
		}
		local, remote, err := connectionEndpoints(connection)
		if err != nil {
			ready <- err
			return
		}
		keys, err := DeriveMiddleKeyData(false, secret, serverNonce.Nonce, clientNonce.Nonce, clientNonce.Timestamp, MiddleEndpoints{Server: local, Client: remote})
		if err != nil {
			ready <- err
			return
		}
		crypto, err := NewMiddleCBC(keys)
		if err != nil {
			ready <- err
			return
		}
		wire := &middleWire{connection: connection, crypto: crypto, maxPayload: 1024, readSequence: -1, writeSequence: -1}
		handshake, err := wire.readMessage()
		ready <- err
		if err != nil {
			return
		}
		select {
		case <-reply:
		case <-ctx.Done():
			return
		}
		if err := wire.writeMessage(handshake); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, connection)
	}()
	type result struct {
		client *MiddleClient
		err    error
	}
	done := make(chan result, 1)
	go func() { client, err := manager.OpenClient(ctx, 1, nil); done <- result{client, err} }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Middle-End handshake not reached")
	}
	upstream.Store(newData)
	if _, err := manager.poolFor(newData); err != nil {
		t.Fatal(err)
	}
	reply <- struct{}{}
	select {
	case got := <-done:
		if got.client != nil {
			got.client.Close()
		}
		if !errors.Is(got.err, ErrMiddleClosed) {
			t.Fatalf("old in-flight dial joined replaced pool: %v", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial did not complete")
	}
}

func TestMiddleMessageDeadlineCoversAllBlocks(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	payload := bytes.Repeat([]byte{1, 2, 3, 4}, 6)
	frame, err := EncodeMiddleRPCFrame(0, payload)
	if err != nil {
		t.Fatal(err)
	}
	for len(frame)%16 != 0 {
		frame = appendUint32(frame, 4)
	}
	encoder, err := NewMiddleCBC(MiddleKeyData{})
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(frame))
	if err := encoder.Encrypt(encrypted, frame); err != nil {
		t.Fatal(err)
	}
	decoder, err := NewMiddleCBC(MiddleKeyData{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write(encrypted) }()
	connection := &readDeadlineConn{Conn: client}
	wire := &middleWire{connection: connection, crypto: decoder, maxPayload: 1024}
	got, err := wire.readMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
	if connection.reads < 2 || connection.firstReadDeadline.IsZero() || connection.deadlineChanged {
		t.Fatal("RPC blocks did not share one fixed read deadline")
	}
}

func TestMiddleReadDeadlineSurvivesSequenceWrap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	frame, err := EncodeMiddleRPCFrame(1<<31, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := NewMiddleCBC(MiddleKeyData{})
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(frame))
	if err := encoder.Encrypt(encrypted, frame); err != nil {
		t.Fatal(err)
	}
	decoder, err := NewMiddleCBC(MiddleKeyData{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write(encrypted) }()
	connection := &readDeadlineConn{Conn: client}
	wire := &middleWire{connection: connection, crypto: decoder, maxPayload: 1024, readSequence: -1 << 31}
	if _, err := wire.readMessage(); err != nil {
		t.Fatal(err)
	}
	if connection.firstReadDeadline.IsZero() {
		t.Fatal("sequence wrap disabled RPC read deadline")
	}
}

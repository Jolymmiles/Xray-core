package mtproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rpcHandshakeOperation uint32 = 0x7682eef5
	middleNonceSequence   uint32 = 0xfffffffe
)

type middleWire struct {
	connection net.Conn
	crypto     *MiddleCBC
	maxPayload int

	writeMu       sync.Mutex
	writeSequence int32
	readSequence  int32
	readBuffer    []byte
}

func (w *middleWire) writeMessage(payload []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	frame, err := EncodeMiddleRPCFrame(uint32(w.writeSequence), payload)
	if err != nil {
		return err
	}
	w.writeSequence++
	for len(frame)%16 != 0 {
		frame = appendUint32(frame, 4)
	}
	encrypted := make([]byte, len(frame))
	if err := w.crypto.Encrypt(encrypted, frame); err != nil {
		return err
	}
	return writeFull(w.connection, encrypted)
}

func (w *middleWire) readMessage() ([]byte, error) {
	for {
		for len(w.readBuffer) < 4 {
			if err := w.readBlock(); err != nil {
				return nil, err
			}
		}
		length := int(binary.LittleEndian.Uint32(w.readBuffer[:4]))
		if length == 4 {
			w.readBuffer = w.readBuffer[4:]
			continue
		}
		if length < 16 || length&3 != 0 || length-12 > w.maxPayload {
			return nil, fmt.Errorf("%w: encrypted frame length %d", ErrInvalidMiddleRPC, length)
		}
		for len(w.readBuffer) < length {
			if err := w.readBlock(); err != nil {
				return nil, err
			}
		}
		frameBytes := append([]byte(nil), w.readBuffer[:length]...)
		w.readBuffer = w.readBuffer[length:]
		frame, err := ReadMiddleRPCFrame(bytes.NewReader(frameBytes), w.maxPayload)
		if err != nil {
			return nil, err
		}
		if frame.Sequence != uint32(w.readSequence) {
			return nil, fmt.Errorf("%w: sequence %d, want %d", ErrInvalidMiddleRPC, frame.Sequence, w.readSequence)
		}
		w.readSequence++
		return frame.Payload, nil
	}
}

func (w *middleWire) readBlock() error {
	var encrypted [16]byte
	if _, err := io.ReadFull(w.connection, encrypted[:]); err != nil {
		return err
	}
	var plain [16]byte
	if err := w.crypto.Decrypt(plain[:], encrypted[:]); err != nil {
		return err
	}
	w.readBuffer = append(w.readBuffer, plain[:]...)
	return nil
}

type processID struct {
	IP    uint32
	Port  uint16
	PID   uint16
	UTime uint32
}

func encodeHandshake(sender, peer processID) []byte {
	payload := make([]byte, 0, 32)
	payload = appendUint32(payload, rpcHandshakeOperation)
	payload = appendUint32(payload, 0)
	payload = appendProcessID(payload, sender)
	return appendProcessID(payload, peer)
}

func appendProcessID(destination []byte, id processID) []byte {
	destination = appendUint32(destination, id.IP)
	destination = appendUint16(destination, id.Port)
	destination = appendUint16(destination, id.PID)
	return appendUint32(destination, id.UTime)
}

func validateHandshake(payload []byte) error {
	if len(payload) != 32 || binary.LittleEndian.Uint32(payload[:4]) != rpcHandshakeOperation || binary.LittleEndian.Uint32(payload[4:8])&0xff != 0 {
		return fmt.Errorf("%w: handshake response", ErrInvalidMiddleRPC)
	}
	return nil
}

func dialMiddleWire(ctx context.Context, endpoint MiddleEndpoint, secret []byte, maxPayload int) (*middleWire, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)))
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))

	local, remote, err := connectionEndpoints(connection)
	if err != nil {
		return nil, err
	}
	var clientNonce [16]byte
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, err
	}
	timestamp := uint32(time.Now().Unix())
	noncePacket, err := NewMiddleClientNonce(secret, timestamp, clientNonce)
	if err != nil {
		return nil, err
	}
	nonceFrame, err := EncodeMiddleRPCFrame(middleNonceSequence, EncodeMiddleNonce(noncePacket))
	if err != nil {
		return nil, err
	}
	if err := writeFull(connection, nonceFrame); err != nil {
		return nil, err
	}
	responseFrame, err := ReadMiddleRPCFrame(connection, 512)
	if err != nil {
		return nil, err
	}
	if responseFrame.Sequence != middleNonceSequence {
		return nil, fmt.Errorf("%w: nonce sequence", ErrInvalidMiddleRPC)
	}
	serverNoncePacket, err := DecodeMiddleNonce(responseFrame.Payload)
	if err != nil {
		return nil, err
	}
	if err := ValidateMiddleServerNonce(serverNoncePacket, secret, uint32(time.Now().Unix())); err != nil {
		return nil, err
	}
	keys, err := DeriveMiddleKeyData(true, secret, serverNoncePacket.Nonce, clientNonce, timestamp, MiddleEndpoints{Server: remote, Client: local})
	if err != nil {
		return nil, err
	}
	cbc, err := NewMiddleCBC(keys)
	if err != nil {
		return nil, err
	}
	wire := &middleWire{connection: connection, crypto: cbc, maxPayload: maxPayload, writeSequence: -1, readSequence: -1}
	sender := processID{IP: numericIPv4(local.Addr()), Port: local.Port(), PID: uint16(os.Getpid()), UTime: timestamp}
	peer := processID{IP: numericIPv4(remote.Addr()), Port: remote.Port()}
	if err := wire.writeMessage(encodeHandshake(sender, peer)); err != nil {
		return nil, err
	}
	handshakeResponse, err := wire.readMessage()
	if err != nil {
		return nil, err
	}
	if err := validateHandshake(handshakeResponse); err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return wire, nil
}

func connectionEndpoints(connection net.Conn) (netip.AddrPort, netip.AddrPort, error) {
	local, err := netip.ParseAddrPort(connection.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	remote, err := netip.ParseAddrPort(connection.RemoteAddr().String())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	return local, remote, nil
}

func numericIPv4(address netip.Addr) uint32 {
	if !address.Is4() {
		return 0
	}
	value := address.As4()
	return binary.BigEndian.Uint32(value[:])
}

type networkMiddleSession struct {
	wire      *middleWire
	core      *MiddleSession
	done      chan struct{}
	closeOnce sync.Once
}

func dialNetworkMiddleSession(ctx context.Context, endpoint MiddleEndpoint, secret []byte, maxPayload, maxClients, queueDepth int) (*networkMiddleSession, error) {
	wire, err := dialMiddleWire(ctx, endpoint, secret, maxPayload)
	if err != nil {
		return nil, err
	}
	networkSession := &networkMiddleSession{wire: wire, done: make(chan struct{})}
	coreSession, err := NewMiddleSession(maxClients, queueDepth, wire.writeMessage)
	if err != nil {
		_ = wire.connection.Close()
		return nil, err
	}
	networkSession.core = coreSession
	go networkSession.readLoop()
	return networkSession, nil
}

func (s *networkMiddleSession) readLoop() {
	for {
		message, err := s.wire.readMessage()
		if err != nil {
			s.Close(err)
			return
		}
		if err := s.core.HandleMessage(message, s.wire.maxPayload); err != nil && err != ErrMiddleBackpressure {
			s.Close(err)
			return
		}
	}
}

type middleManager struct {
	config     *UpstreamConfig
	upstream   *atomic.Pointer[UpstreamData]
	maxPayload int
	pool       *MiddlePool

	connectMu    sync.Mutex
	sessionsMu   sync.Mutex
	sessions     []*networkMiddleSession
	nextEndpoint map[int16]int
	closed       bool
}

func newMiddleManager(config *UpstreamConfig, upstream *atomic.Pointer[UpstreamData], maxPayload int) (*middleManager, error) {
	data := upstream.Load()
	if data == nil || data.Config == nil {
		return nil, fmt.Errorf("mtproxy: upstream configuration is unavailable")
	}
	pool, err := NewMiddlePool(data.Config.DefaultDC, int(config.MaxSessionsPerDc))
	if err != nil {
		return nil, err
	}
	return &middleManager{config: config, upstream: upstream, maxPayload: maxPayload, pool: pool, nextEndpoint: make(map[int16]int)}, nil
}

func (m *middleManager) OpenClient(ctx context.Context, dcID int16, onClose func()) (*MiddleClient, error) {
	if data := m.upstream.Load(); data != nil && data.Config != nil {
		m.pool.SetDefaultDC(data.Config.DefaultDC)
	}
	if client, err := m.pool.OpenClient(dcID, onClose); err == nil {
		return client, nil
	}
	m.connectMu.Lock()
	defer m.connectMu.Unlock()
	if client, err := m.pool.OpenClient(dcID, onClose); err == nil {
		return client, nil
	}
	m.sessionsMu.Lock()
	closed := m.closed
	m.sessionsMu.Unlock()
	if closed {
		return nil, ErrMiddleClosed
	}
	data := m.upstream.Load()
	if data == nil || data.Config == nil {
		return nil, ErrMiddleClosed
	}
	targetDC := dcID
	endpoints := data.Config.clusters[targetDC]
	if len(endpoints) == 0 {
		targetDC = data.Config.DefaultDC
		endpoints = data.Config.clusters[targetDC]
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("mtproxy: no Middle-End endpoint for DC %d", dcID)
	}
	index := m.nextEndpoint[targetDC] % len(endpoints)
	m.nextEndpoint[targetDC]++
	networkSession, err := dialNetworkMiddleSession(ctx, endpoints[index], data.Secret, m.maxPayload, int(m.config.MaxClientsPerSession), int(m.config.DeliveryQueueDepth))
	if err != nil {
		return nil, err
	}
	if err := m.pool.AddSession(targetDC, networkSession.core); err != nil {
		networkSession.Close(err)
		return nil, err
	}
	m.sessionsMu.Lock()
	if m.closed {
		m.sessionsMu.Unlock()
		networkSession.Close(ErrMiddleClosed)
		return nil, ErrMiddleClosed
	}
	activeSessions := m.sessions[:0]
	for _, existing := range m.sessions {
		if _, closed := existing.core.load(); !closed {
			activeSessions = append(activeSessions, existing)
		}
	}
	m.sessions = append(activeSessions, networkSession)
	m.sessionsMu.Unlock()
	return networkSession.core.OpenClient(onClose)
}

func (m *middleManager) Close() {
	m.sessionsMu.Lock()
	if m.closed {
		m.sessionsMu.Unlock()
		return
	}
	m.closed = true
	sessions := append([]*networkMiddleSession(nil), m.sessions...)
	m.sessions = nil
	m.sessionsMu.Unlock()
	for _, session := range sessions {
		session.Close(ErrMiddleClosed)
	}
}

func (s *networkMiddleSession) Close(reason error) {
	s.closeOnce.Do(func() {
		_ = s.wire.connection.Close()
		s.core.Fail(reason)
		close(s.done)
	})
}

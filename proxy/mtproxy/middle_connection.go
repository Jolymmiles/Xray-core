package mtproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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
	middleRPCUseCRC32C    uint32 = 2048
)

type middleWire struct {
	connection net.Conn
	crypto     *MiddleCBC
	maxPayload int

	writeMu       sync.Mutex
	writeSequence int32
	readSequence  int32
	readBuffer    []byte
	crcTable      *crc32.Table
}

func (w *middleWire) writeMessage(payload []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_ = w.connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer w.connection.SetWriteDeadline(time.Time{})
	frame, err := encodeMiddleRPCFrame(uint32(w.writeSequence), payload, w.crcTable)
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
		frame, err := readMiddleRPCFrame(bytes.NewReader(frameBytes), w.maxPayload, w.crcTable)
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
	_ = w.connection.SetReadDeadline(time.Now().Add(5 * time.Minute))
	defer w.connection.SetReadDeadline(time.Time{})
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
	payload = appendUint32(payload, middleRPCUseCRC32C)
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
	if len(payload) != 32 || binary.LittleEndian.Uint32(payload[:4]) != rpcHandshakeOperation || binary.LittleEndian.Uint32(payload[4:8]) != middleRPCUseCRC32C {
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
	wire.crcTable = crc32.MakeTable(crc32.Castagnoli)
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
	wire             *middleWire
	clientMaxPayload int
	upstream         *UpstreamData
	core             *MiddleSession
	done             chan struct{}
	closeOnce        sync.Once
}

func dialNetworkMiddleSession(ctx context.Context, endpoint MiddleEndpoint, secret []byte, maxPayload, maxClients, queueDepth int) (*networkMiddleSession, error) {
	wire, err := dialMiddleWire(ctx, endpoint, secret, maxPayload+64)
	if err != nil {
		return nil, err
	}
	networkSession := &networkMiddleSession{wire: wire, clientMaxPayload: maxPayload, done: make(chan struct{})}
	coreSession, err := NewMiddleSession(maxClients, queueDepth, wire.writeMessage)
	if err != nil {
		_ = wire.connection.Close()
		return nil, err
	}
	networkSession.core = coreSession
	coreSession.SetWriteFailureHandler(networkSession.Close)
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
		if err := s.core.HandleMessage(message, s.clientMaxPayload); err != nil && err != ErrMiddleBackpressure {
			s.Close(err)
			return
		}
	}
}

type middleManager struct {
	config          *UpstreamConfig
	upstream        *atomic.Pointer[UpstreamData]
	maxPayload      int
	poolMu          sync.Mutex
	pool            *MiddlePool
	appliedUpstream *UpstreamData

	connectSlot  chan struct{}
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
	return &middleManager{config: config, upstream: upstream, maxPayload: maxPayload, pool: pool, appliedUpstream: data, connectSlot: make(chan struct{}, 1), nextEndpoint: make(map[int16]int)}, nil
}

func (m *middleManager) OpenClient(ctx context.Context, dcID int16, onClose func()) (*MiddleClient, error) {
	data := m.upstream.Load()
	targetDC, endpoints, err := resolveMiddleTarget(data, dcID)
	if err != nil {
		return nil, err
	}
	pool, err := m.poolFor(data)
	if err != nil {
		return nil, err
	}
	if client, err := pool.OpenClientExact(targetDC, onClose); err == nil {
		return client, nil
	}
	select {
	case m.connectSlot <- struct{}{}:
		defer func() { <-m.connectSlot }()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrMiddleCapacity
	}
	data = m.upstream.Load()
	targetDC, endpoints, err = resolveMiddleTarget(data, dcID)
	if err != nil {
		return nil, err
	}
	pool, err = m.poolFor(data)
	if err != nil {
		return nil, err
	}
	if client, err := pool.OpenClientExact(targetDC, onClose); err == nil {
		return client, nil
	}
	m.sessionsMu.Lock()
	closed := m.closed
	m.sessionsMu.Unlock()
	if closed {
		return nil, ErrMiddleClosed
	}
	startIndex := m.nextEndpoint[targetDC] % len(endpoints)
	m.nextEndpoint[targetDC]++
	var networkSession *networkMiddleSession
	var dialErr error
	for attempt := 0; attempt < len(endpoints); attempt++ {
		endpoint := endpoints[(startIndex+attempt)%len(endpoints)]
		networkSession, dialErr = dialNetworkMiddleSession(ctx, endpoint, data.Secret, m.maxPayload, int(m.config.MaxClientsPerSession), int(m.config.DeliveryQueueDepth))
		if dialErr == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if networkSession == nil {
		return nil, fmt.Errorf("mtproxy: all Middle-End endpoints for DC %d failed: %w", targetDC, dialErr)
	}
	networkSession.upstream = data
	if err := pool.AddSession(targetDC, networkSession.core); err != nil {
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

func (m *middleManager) poolFor(data *UpstreamData) (*MiddlePool, error) {
	m.retireIdleSessions(data)
	m.poolMu.Lock()
	defer m.poolMu.Unlock()
	if m.appliedUpstream == data {
		return m.pool, nil
	}
	if m.appliedUpstream != nil && data.LoadedAt.Before(m.appliedUpstream.LoadedAt) {
		return m.pool, nil
	}
	pool, err := NewMiddlePool(data.Config.DefaultDC, int(m.config.MaxSessionsPerDc))
	if err != nil {
		return nil, err
	}
	m.pool = pool
	m.appliedUpstream = data
	return pool, nil
}

func (m *middleManager) retireIdleSessions(current *UpstreamData) {
	m.sessionsMu.Lock()
	active := m.sessions[:0]
	retired := make([]*networkMiddleSession, 0)
	for _, session := range m.sessions {
		count, closed := session.core.load()
		if closed {
			continue
		}
		if session.upstream != nil && session.upstream != current && count == 0 {
			retired = append(retired, session)
			continue
		}
		active = append(active, session)
	}
	m.sessions = active
	m.sessionsMu.Unlock()
	for _, session := range retired {
		session.Close(ErrMiddleClosed)
	}
}

func resolveMiddleTarget(data *UpstreamData, requestedDC int16) (int16, []MiddleEndpoint, error) {
	if data == nil || data.Config == nil {
		return 0, nil, ErrMiddleClosed
	}
	targetDC := requestedDC
	endpoints := data.Config.clusters[targetDC]
	if len(endpoints) == 0 {
		targetDC = data.Config.DefaultDC
		endpoints = data.Config.clusters[targetDC]
	}
	if len(endpoints) == 0 {
		return 0, nil, fmt.Errorf("mtproxy: no Middle-End endpoint for DC %d", requestedDC)
	}
	return targetDC, endpoints, nil
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

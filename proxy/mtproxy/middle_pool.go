package mtproxy

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrMiddleBackpressure = errors.New("mtproxy: Middle-End client delivery queue is full")
	ErrMiddleCapacity     = errors.New("mtproxy: Middle-End session client capacity reached")
	ErrMiddleClosed       = errors.New("mtproxy: Middle-End session is closed")
)

type MiddleDeliveryKind uint8

const (
	MiddleDeliveryPayload MiddleDeliveryKind = iota + 1
	MiddleDeliveryAck
)

type MiddleDelivery struct {
	Kind    MiddleDeliveryKind
	Flags   uint32
	Payload []byte
	Confirm uint32
}

type MiddleClient struct {
	session *MiddleSession
	id      uint64
	queue   chan MiddleDelivery

	closeOnce sync.Once
	onClose   func()
}

func (c *MiddleClient) ID() uint64                        { return c.id }
func (c *MiddleClient) Deliveries() <-chan MiddleDelivery { return c.queue }

func (c *MiddleClient) Send(request ProxyRequest) error {
	if c == nil || c.session == nil {
		return ErrMiddleClosed
	}
	return c.session.sendRequest(c, request)
}

// Close removes only this logical client. The shared physical Middle-End
// session remains available to clients authenticated by other secrets.
func (c *MiddleClient) Close() {
	if c == nil || c.session == nil {
		return
	}
	c.closeOnce.Do(func() { c.session.closeClient(c.id, true) })
}

type MiddleSession struct {
	maxClients int
	queueDepth int
	write      func([]byte) error

	mu      sync.Mutex
	closed  bool
	nextID  uint64
	clients map[uint64]*MiddleClient

	writeMu sync.Mutex
}

func NewMiddleSession(maxClients, queueDepth int, writeMessage func([]byte) error) (*MiddleSession, error) {
	if maxClients <= 0 || queueDepth <= 0 || writeMessage == nil {
		return nil, fmt.Errorf("mtproxy: invalid Middle-End session limits")
	}
	return &MiddleSession{
		maxClients: maxClients,
		queueDepth: queueDepth,
		write:      writeMessage,
		clients:    make(map[uint64]*MiddleClient, maxClients),
	}, nil
}

func (s *MiddleSession) OpenClient(onClose func()) (*MiddleClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrMiddleClosed
	}
	if len(s.clients) >= s.maxClients {
		return nil, ErrMiddleCapacity
	}
	for {
		s.nextID++
		if s.nextID == 0 {
			continue
		}
		if _, exists := s.clients[s.nextID]; exists {
			continue
		}
		client := &MiddleClient{
			session: s,
			id:      s.nextID,
			queue:   make(chan MiddleDelivery, s.queueDepth),
			onClose: onClose,
		}
		s.clients[client.id] = client
		return client, nil
	}
}

func (s *MiddleSession) sendRequest(client *MiddleClient, request ProxyRequest) error {
	s.mu.Lock()
	active := !s.closed && s.clients[client.id] == client
	s.mu.Unlock()
	if !active {
		return ErrMiddleClosed
	}
	request.ConnectionID = client.id
	encoded, err := EncodeProxyRequest(request)
	if err != nil {
		return err
	}
	return s.writeMessage(encoded)
}

func (s *MiddleSession) writeMessage(message []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrMiddleClosed
	}
	return s.write(message)
}

func (s *MiddleSession) HandleMessage(encoded []byte, maxPayload int) error {
	message, err := DecodeMiddleMessage(encoded, maxPayload)
	if err != nil {
		return err
	}

	var connectionID uint64
	var delivery MiddleDelivery
	closeOnly := false
	switch value := message.(type) {
	case ProxyAnswer:
		connectionID = value.ConnectionID
		delivery = MiddleDelivery{Kind: MiddleDeliveryPayload, Flags: value.Flags, Payload: value.Payload}
	case SimpleAck:
		connectionID = value.ConnectionID
		delivery = MiddleDelivery{Kind: MiddleDeliveryAck, Confirm: value.Confirm}
	case CloseExternal:
		connectionID = value.ConnectionID
		closeOnly = true
	case CloseConnection:
		connectionID = value.ConnectionID
		closeOnly = true
	default:
		return ErrInvalidMiddleRPC
	}

	if closeOnly {
		s.closeClient(connectionID, false)
		return nil
	}

	s.mu.Lock()
	client := s.clients[connectionID]
	if client == nil {
		s.mu.Unlock()
		_ = s.writeMessage(EncodeCloseConnection(CloseConnection{ConnectionID: connectionID}))
		return nil
	}
	select {
	case client.queue <- delivery:
		s.mu.Unlock()
		return nil
	default:
		delete(s.clients, connectionID)
		close(client.queue)
		callback := client.onClose
		s.mu.Unlock()
		if callback != nil {
			callback()
		}
		_ = s.writeMessage(EncodeCloseConnection(CloseConnection{ConnectionID: connectionID}))
		return ErrMiddleBackpressure
	}
}

func (s *MiddleSession) closeClient(connectionID uint64, notifyRemote bool) {
	s.mu.Lock()
	client := s.clients[connectionID]
	if client != nil {
		delete(s.clients, connectionID)
		close(client.queue)
	}
	s.mu.Unlock()
	if client == nil {
		return
	}
	if client.onClose != nil {
		client.onClose()
	}
	if notifyRemote {
		_ = s.writeMessage(EncodeCloseConnection(CloseConnection{ConnectionID: connectionID}))
	}
}

type MiddlePool struct {
	defaultDC        int16
	maxSessionsPerDC int

	mu       sync.RWMutex
	sessions map[int16][]*MiddleSession
}

func NewMiddlePool(defaultDC int16, maxSessionsPerDC int) (*MiddlePool, error) {
	if maxSessionsPerDC <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid Middle-End pool session limit %d", maxSessionsPerDC)
	}
	return &MiddlePool{
		defaultDC:        defaultDC,
		maxSessionsPerDC: maxSessionsPerDC,
		sessions:         make(map[int16][]*MiddleSession),
	}, nil
}

func (p *MiddlePool) SetDefaultDC(dcID int16) {
	p.mu.Lock()
	p.defaultDC = dcID
	p.mu.Unlock()
}

func (p *MiddlePool) AddSession(dcID int16, session *MiddleSession) error {
	if session == nil {
		return ErrMiddleClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.sessions[dcID]
	active := current[:0]
	for _, existing := range current {
		if _, closed := existing.load(); !closed {
			active = append(active, existing)
		}
	}
	current = active
	p.sessions[dcID] = current
	if len(current) >= p.maxSessionsPerDC {
		return ErrMiddleCapacity
	}
	for _, existing := range current {
		if existing == session {
			return nil
		}
	}
	p.sessions[dcID] = append(current, session)
	return nil
}

func (p *MiddlePool) OpenClient(dcID int16, onClose func()) (*MiddleClient, error) {
	p.mu.RLock()
	candidates := append([]*MiddleSession(nil), p.sessions[dcID]...)
	if len(candidates) == 0 {
		candidates = append(candidates, p.sessions[p.defaultDC]...)
	}
	p.mu.RUnlock()
	if len(candidates) == 0 {
		return nil, ErrMiddleClosed
	}

	for len(candidates) > 0 {
		bestIndex := -1
		bestLoad := int(^uint(0) >> 1)
		for index, session := range candidates {
			load, closed := session.load()
			if !closed && load < bestLoad {
				bestIndex, bestLoad = index, load
			}
		}
		if bestIndex < 0 {
			return nil, ErrMiddleClosed
		}
		client, err := candidates[bestIndex].OpenClient(onClose)
		if err == nil {
			return client, nil
		}
		if !errors.Is(err, ErrMiddleCapacity) && !errors.Is(err, ErrMiddleClosed) {
			return nil, err
		}
		candidates = append(candidates[:bestIndex], candidates[bestIndex+1:]...)
	}
	return nil, ErrMiddleCapacity
}

func (s *MiddleSession) load() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients), s.closed
}

// Fail terminates every logical client exactly once and permanently rejects new
// clients. It never invokes the writer while holding session state locks.
func (s *MiddleSession) Fail(_ error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	clients := make([]*MiddleClient, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
		close(client.queue)
	}
	clear(s.clients)
	s.mu.Unlock()

	for _, client := range clients {
		if client.onClose != nil {
			client.onClose()
		}
	}
}

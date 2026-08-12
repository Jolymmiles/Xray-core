package mux

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

var nextRuntimeID atomic.Uint64

// Runtime owns reusable mux state and its single expiry scheduler.
type Runtime struct {
	id           uint64
	mu           sync.Mutex
	flows        map[xudpRuntimeKey]*xudpFlow
	sinks        map[*xudpResponseSink]struct{}
	nextWorker   uint64
	nextTxn      uint64
	transactions map[uint64]context.CancelFunc
	closing      bool
	expiry       time.Duration
	stop         chan struct{}
	done         chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	pumps        sync.WaitGroup
	txns         sync.WaitGroup
}

func newRuntime() *Runtime {
	id := nextRuntimeID.Add(1)
	if id == 0 {
		id = nextRuntimeID.Add(1)
	}
	return &Runtime{
		id:           id,
		flows:        make(map[xudpRuntimeKey]*xudpFlow),
		sinks:        make(map[*xudpResponseSink]struct{}),
		transactions: make(map[uint64]context.CancelFunc),
		expiry:       time.Minute,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
}

func (r *Runtime) beginTransaction(parent context.Context) (context.Context, func(), bool) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return nil, nil, false
	}
	r.nextTxn++
	if r.nextTxn == 0 {
		r.nextTxn++
	}
	id := r.nextTxn
	ctx, cancel := context.WithCancel(parent)
	r.transactions[id] = cancel
	r.txns.Add(1)
	r.mu.Unlock()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.transactions, id)
			r.mu.Unlock()
			cancel()
			r.txns.Done()
		})
	}, true
}

func (r *Runtime) workerToken() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return 0
	}
	r.nextWorker++
	if r.nextWorker == 0 {
		r.nextWorker++
	}
	return r.nextWorker
}

type xudpRuntimeKey struct {
	principal [32]byte
	globalID  [8]byte
	worker    uint64
}

func (r *Runtime) xudpKey(scope session.PresenceScope, worker uint64, globalID [8]byte) xudpRuntimeKey {
	subject := scope.Subject()
	key := xudpRuntimeKey{globalID: globalID}
	if subject.Reusable && subject.PrincipalKey != ([32]byte{}) {
		key.principal = subject.PrincipalKey
	} else {
		key.worker = worker
	}
	return key
}

type xudpDestination struct {
	network net.Network
	address string
	port    net.Port
}

func freezeXUDPDestination(destination net.Destination) xudpDestination {
	address := ""
	if destination.Address != nil {
		address = destination.Address.String()
	}
	return xudpDestination{network: destination.Network, address: address, port: destination.Port}
}

func (d xudpDestination) matches(destination net.Destination) bool {
	return d == freezeXUDPDestination(destination)
}

func (r *Runtime) startScheduler() {
	r.startOnce.Do(func() { go r.scheduleExpiry() })
}

func (r *Runtime) scheduleExpiry() {
	defer close(r.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			r.expire(now)
		case <-r.stop:
			return
		}
	}
}

func (r *Runtime) expire(now time.Time) {
	var expired []*xudpFlow
	r.mu.Lock()
	for key, flow := range r.flows {
		if flow.expired(now) {
			delete(r.flows, key)
			expired = append(expired, flow)
		}
	}
	r.mu.Unlock()
	for _, flow := range expired {
		flow.close()
	}
}

func (r *Runtime) removeFlow(key xudpRuntimeKey, flow *xudpFlow) {
	r.mu.Lock()
	if r.flows[key] == flow {
		delete(r.flows, key)
	}
	r.mu.Unlock()
	flow.close()
}

// Close stops admission, drains flows and waits for every backend pump.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		var flows []*xudpFlow
		var sinks []*xudpResponseSink
		var cancels []context.CancelFunc
		r.mu.Lock()
		r.closing = true
		for key, flow := range r.flows {
			delete(r.flows, key)
			flows = append(flows, flow)
		}
		for sink := range r.sinks {
			delete(r.sinks, sink)
			sinks = append(sinks, sink)
		}
		for _, cancel := range r.transactions {
			cancels = append(cancels, cancel)
		}
		r.mu.Unlock()
		close(r.stop)
		for _, cancel := range cancels {
			cancel()
		}
		for _, flow := range flows {
			flow.close()
		}
		for _, sink := range sinks {
			sink.close()
		}
		if started := func() bool {
			started := false
			r.startOnce.Do(func() { started = true; close(r.done) })
			return !started
		}(); started {
			<-r.done
		}
		r.pumps.Wait()
		r.txns.Wait()
	})
	return nil
}

type xudpFlow struct {
	runtime    *Runtime
	key        xudpRuntimeKey
	target     xudpDestination
	backend    *transport.Link
	mu         sync.Mutex
	cond       *sync.Cond
	attachment *xudpAttachment
	nextEpoch  uint64
	rebinding  bool
	expires    time.Time
	closed     bool
	closeOnce  sync.Once
}

type xudpAttachment struct {
	token   uint64
	session *Session
	sink    *xudpResponseSink
}

func newXUDPFlow(runtime *Runtime, key xudpRuntimeKey, target net.Destination, backend *transport.Link) *xudpFlow {
	flow := &xudpFlow{runtime: runtime, key: key, target: freezeXUDPDestination(target), backend: backend}
	flow.cond = sync.NewCond(&flow.mu)
	runtime.pumps.Add(1)
	go flow.pump()
	return flow
}

func (r *Runtime) xudpFlow(ctx context.Context, key xudpRuntimeKey, target net.Destination, dispatcher routing.Dispatcher) (*xudpFlow, error) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return nil, errors.New("mux runtime is closing")
	}
	if flow := r.flows[key]; flow != nil {
		r.mu.Unlock()
		if !flow.target.matches(target) {
			return nil, errors.New("XUDP destination changed")
		}
		return flow, nil
	}
	r.mu.Unlock()

	backendCtx := session.ContextWithPresenceMode(ctx, session.PresenceModeUntracked)
	backend, err := dispatcher.Dispatch(backendCtx, target)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		common.Interrupt(backend.Reader)
		common.Close(backend.Writer)
		return nil, errors.New("mux runtime is closing")
	}
	if existing := r.flows[key]; existing != nil {
		r.mu.Unlock()
		common.Interrupt(backend.Reader)
		common.Close(backend.Writer)
		if !existing.target.matches(target) {
			return nil, errors.New("XUDP destination changed")
		}
		return existing, nil
	}
	candidate := newXUDPFlow(r, key, target, backend)
	r.flows[key] = candidate
	r.mu.Unlock()
	r.startScheduler()
	return candidate, nil
}

func (f *xudpFlow) attach(admission *sessionAdmission, scope session.PresenceScope, sink *xudpResponseSink) (*Session, error) {
	reservation := scope.Prepare()
	f.mu.Lock()
	if f.closed || f.rebinding {
		f.mu.Unlock()
		reservation.Abort()
		return nil, errors.New("XUDP flow cannot accept attachment")
	}
	f.rebinding = true
	f.nextEpoch++
	epoch := f.nextEpoch
	old := f.attachment
	f.mu.Unlock()

	if !admission.beginCommit() {
		f.finishRebind()
		reservation.Abort()
		return nil, errors.New("XUDP attachment commit rejected")
	}
	var lease session.PresenceLease
	if old != nil {
		lease = reservation.Handoff(old.session.presenceLease)
	} else {
		lease = reservation.Activate()
	}
	owner := &Session{
		output:       f.backend.Writer,
		transferType: protocol.TransferTypePacket,
	}
	owner.release = func() { f.detach(epoch) }
	if !admission.finishCommit(owner, lease) {
		f.finishRebind()
		if old != nil {
			_ = old.session.Close(false)
		}
		return nil, errors.New("XUDP attachment publication rejected")
	}

	f.mu.Lock()
	if f.closed || owner.terminated.Load() {
		f.rebinding = false
		f.mu.Unlock()
		_ = owner.Close(false)
		return nil, errors.New("XUDP flow closed during attachment")
	}
	f.attachment = &xudpAttachment{token: epoch, session: owner, sink: sink}
	f.expires = time.Time{}
	f.rebinding = false
	f.cond.Broadcast()
	f.mu.Unlock()
	if old != nil {
		_ = old.session.Close(false)
	}
	return owner, nil
}

func (f *xudpFlow) finishRebind() {
	f.mu.Lock()
	f.rebinding = false
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *xudpFlow) expired(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachment == nil && !f.expires.IsZero() && !now.Before(f.expires)
}

func (f *xudpFlow) detach(token uint64) {
	f.mu.Lock()
	if f.attachment != nil && f.attachment.token == token {
		f.attachment = nil
		f.expires = time.Now().Add(f.runtime.expiry)
	}
	f.mu.Unlock()
}

func (f *xudpFlow) close() {
	f.closeOnce.Do(func() {
		var attachment *xudpAttachment
		f.mu.Lock()
		f.closed = true
		attachment = f.attachment
		f.attachment = nil
		f.cond.Broadcast()
		f.mu.Unlock()
		if attachment != nil {
			_ = attachment.session.Close(false)
		}
		common.Interrupt(f.backend.Reader)
		common.Close(f.backend.Writer)
	})
}

func (f *xudpFlow) pump() {
	defer f.runtime.pumps.Done()
	for {
		f.mu.Lock()
		for f.attachment == nil && !f.closed {
			f.cond.Wait()
		}
		if f.closed {
			f.mu.Unlock()
			return
		}
		attachment := f.attachment
		f.mu.Unlock()

		payload, err := f.backend.Reader.ReadMultiBuffer()
		if err != nil {
			f.runtime.removeFlow(f.key, f)
			return
		}
		f.mu.Lock()
		if f.attachment != nil {
			attachment = f.attachment
		} else {
			attachment = nil
		}
		f.mu.Unlock()
		if attachment == nil {
			payload = buf.ReleaseMulti(payload)
			continue
		}
		if !attachment.sink.enqueue(attachment.session.ID, payload) {
			_ = attachment.session.Close(false)
		}
	}
}

type xudpResponse struct {
	id      uint16
	payload buf.MultiBuffer
}

type xudpResponseSink struct {
	runtime *Runtime
	output  buf.Writer
	queue   chan xudpResponse
	stop    chan struct{}
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
}

func (r *Runtime) newResponseSink(output buf.Writer) *xudpResponseSink {
	sink := &xudpResponseSink{
		runtime: r,
		output:  output,
		queue:   make(chan xudpResponse, 64),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		close(sink.stop)
		close(sink.done)
		return sink
	}
	r.sinks[sink] = struct{}{}
	r.mu.Unlock()
	go sink.run()
	return sink
}

func (s *xudpResponseSink) enqueue(id uint16, payload buf.MultiBuffer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		buf.ReleaseMulti(payload)
		return false
	}
	select {
	case s.queue <- xudpResponse{id: id, payload: payload}:
		return true
	default:
		buf.ReleaseMulti(payload)
		return false
	}
}

func (s *xudpResponseSink) run() {
	defer close(s.done)
	for {
		select {
		case response := <-s.queue:
			writer := NewResponseWriter(response.id, s.output, protocol.TransferTypePacket)
			if err := writer.WriteMultiBuffer(response.payload); err != nil {
				s.markClosed()
				s.closeOutput()
				for {
					select {
					case response := <-s.queue:
						buf.ReleaseMulti(response.payload)
					default:
						return
					}
				}
			}
		case <-s.stop:
			for {
				select {
				case response := <-s.queue:
					buf.ReleaseMulti(response.payload)
				default:
					return
				}
			}
		}
	}
}

func (s *xudpResponseSink) closeOutput() {
	common.Interrupt(s.output)
}

func (s *xudpResponseSink) markClosed() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.stop)
	}
	s.mu.Unlock()
}

func (s *xudpResponseSink) close() {
	s.markClosed()
	s.closeOutput()
	<-s.done
	s.runtime.mu.Lock()
	delete(s.runtime.sinks, s)
	s.runtime.mu.Unlock()
}

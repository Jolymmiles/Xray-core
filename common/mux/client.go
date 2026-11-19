package mux

import (
	"context"
	goerrors "errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type ClientManager struct {
	Enabled bool // whether mux is enabled from user config
	Picker  WorkerPicker
}

func (m *ClientManager) Dispatch(ctx context.Context, link *transport.Link) error {
	return m.dispatch(ctx, link, false)
}

// DispatchRVS publishes one reverse data session on its selected carrier.
func (m *ClientManager) DispatchRVS(ctx context.Context, link *transport.Link) error {
	return m.dispatch(ctx, link, true)
}

func (m *ClientManager) dispatch(ctx context.Context, link *transport.Link, rvs bool) error {
	for i := 0; i < 16; i++ {
		worker, err := m.Picker.PickAvailable()
		if err != nil {
			return err
		}
		var accepted bool
		if rvs {
			accepted = worker.DispatchRVS(ctx, link)
		} else {
			accepted = worker.Dispatch(ctx, link)
		}
		if accepted {
			return nil
		}
	}

	return errors.New("unable to find an available mux client")
}

type WorkerPicker interface {
	PickAvailable() (*ClientWorker, error)
}

type IncrementalWorkerPicker struct {
	Factory ClientWorkerFactory

	access      sync.Mutex
	workers     []*ClientWorker
	cleanupTask *task.Periodic
}

func (p *IncrementalWorkerPicker) cleanupFunc() error {
	p.access.Lock()
	defer p.access.Unlock()

	if len(p.workers) == 0 {
		return errors.New("no worker")
	}

	p.cleanup()
	return nil
}

func (p *IncrementalWorkerPicker) cleanup() {
	var activeWorkers []*ClientWorker
	for _, w := range p.workers {
		if !w.Closed() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	p.workers = activeWorkers
}

func (p *IncrementalWorkerPicker) findAvailable() int {
	for idx, w := range p.workers {
		if !w.IsFull() {
			return idx
		}
	}

	return -1
}

func (p *IncrementalWorkerPicker) pickInternal() (*ClientWorker, bool, error) {
	p.access.Lock()
	defer p.access.Unlock()

	idx := p.findAvailable()
	if idx >= 0 {
		n := len(p.workers)
		if n > 1 && idx != n-1 {
			p.workers[n-1], p.workers[idx] = p.workers[idx], p.workers[n-1]
		}
		return p.workers[idx], false, nil
	}

	p.cleanup()

	worker, err := p.Factory.Create()
	if err != nil {
		return nil, false, err
	}
	p.workers = append(p.workers, worker)

	if p.cleanupTask == nil {
		p.cleanupTask = &task.Periodic{
			Interval: time.Second * 30,
			Execute:  p.cleanupFunc,
		}
	}

	return worker, true, nil
}

func (p *IncrementalWorkerPicker) PickAvailable() (*ClientWorker, error) {
	worker, start, err := p.pickInternal()
	if start {
		common.Must(p.cleanupTask.Start())
	}

	return worker, err
}

type ClientWorkerFactory interface {
	Create() (*ClientWorker, error)
}

type DialingWorkerFactory struct {
	Proxy    proxy.Outbound
	Dialer   internet.Dialer
	Strategy ClientStrategy
}

func (f *DialingWorkerFactory) Create() (*ClientWorker, error) {
	opts := []pipe.Option{pipe.WithSizeLimit(64 * 1024)}
	uplinkReader, upLinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	c, err := NewClientWorker(transport.Link{
		Reader: downlinkReader,
		Writer: upLinkWriter,
	}, f.Strategy)
	if err != nil {
		return nil, err
	}

	go func(p proxy.Outbound, d internet.Dialer, c common.Closable) {
		outbounds := []*session.Outbound{{
			Target: net.TCPDestination(muxCoolAddress, muxCoolPort),
		}}
		ctx := session.ContextWithOutbounds(context.Background(), outbounds)
		ctx, cancel := context.WithCancel(ctx)

		if errP := p.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, d); errP != nil {
			errC := errors.Cause(errP)
			if !(goerrors.Is(errC, io.EOF) || goerrors.Is(errC, io.ErrClosedPipe) || goerrors.Is(errC, context.Canceled)) {
				errors.LogInfoInner(ctx, errP, "failed to handler mux client connection")
			}
		}
		// The carrier has returned. Closing its end of the downlink lets
		// fetchOutput deliver what the carrier had written, as far as the
		// sessions take it, and then finish the worker, which ends the
		// sessions. A carrier that failed leaves that end open; fetchOutput
		// then waits on it for good and the sessions stay open and silent.
		// Interrupting the downlink here instead would drop a response
		// already received. A carrier that returns on its first error may
		// still be copying the response: what that copy holds and has not
		// written yet is dropped by this close.
		common.Close(downlinkWriter)
		common.Must(c.Close())
		// The uplink has lost its reader, or will with the carrier's last
		// copy. Left open it fills, and a write to it would hold fetchOutput,
		// which answers a reply for a closed session with an END, away from
		// the end of the downlink and so from finish(). Interrupted, it
		// fails every write: fetchInput then drops what its session still
		// uploads and leaves the session to finish(), the worker being
		// closed by now.
		common.Interrupt(uplinkReader)
		cancel()
	}(f.Proxy, f.Dialer, c.done)

	return c, nil
}

type ClientStrategy struct {
	MaxConcurrency uint32
	// MaxConnection is how many sessions a worker admits over its lifetime,
	// aborted admissions included; 0 means no limit. Outbounds take it from
	// mux.maxReuseTimes.
	MaxConnection uint32
}

type ClientWorker struct {
	sessionManager *clientSessionManager
	link           transport.Link
	done           *done.Instance
	timer          *time.Ticker
	strategy       ClientStrategy
	finishOnce     sync.Once
	presence       session.PresenceScope
}

var (
	muxCoolAddress = net.DomainAddress("v1.mux.cool")
	muxCoolPort    = net.Port(9527)
)

// NewClientWorker creates a new mux.Client.
func NewClientWorker(stream transport.Link, s ClientStrategy) (*ClientWorker, error) {
	return NewClientWorkerWithPresence(stream, s, session.PresenceScope{})
}

// NewClientWorkerWithPresence binds an authenticated carrier scope to RVS
// data sessions while leaving control and ordinary mux sessions untracked.
func NewClientWorkerWithPresence(stream transport.Link, s ClientStrategy, presence session.PresenceScope) (*ClientWorker, error) {
	stream.Writer = &MutexWriter{Writer: stream.Writer}
	c := &ClientWorker{
		sessionManager: newClientSessionManager(),
		link:           stream,
		done:           done.New(),
		timer:          time.NewTicker(time.Second * 16),
		strategy:       s,
		presence:       presence,
	}

	go c.fetchOutput()
	go c.monitor()

	return c, nil
}

func (m *ClientWorker) TotalConnections() uint32 {
	return uint32(m.sessionManager.count())
}

func (m *ClientWorker) ActiveConnections() uint32 {
	return uint32(m.sessionManager.activeCount())
}

// Closed returns true if this Client is closed: a dispatch that sees it is
// refused. finish() closes it after its cleanup. A dialing worker is closed
// earlier, when its carrier returns, and cleaned up once the downlink is
// drained.
func (m *ClientWorker) Closed() bool {
	return m.done.Done()
}

func (m *ClientWorker) WaitClosed() <-chan struct{} {
	return m.done.Wait()
}

// finish tears down sessions and the carrier link, then signals done, unless
// a dialing worker's carrier has signalled it already. As with ServerWorker,
// done/WaitClosed do not join fetchOutput: when Close or monitor calls
// finish, fetchOutput can still be returning from a read of the link. A
// caller must not release what the link reads (VLESS Process leaves its
// reader to a reverse bridge's worker).
func (m *ClientWorker) finish() {
	m.finishOnce.Do(func() {
		m.sessionManager.close()
		common.Interrupt(m.link.Writer)
		common.Interrupt(m.link.Reader)
		common.Must(m.done.Close())
	})
}

func (m *ClientWorker) Close() error {
	m.finish()
	return nil
}

func (m *ClientWorker) monitor() {
	defer m.timer.Stop()

	for {
		checkSize := m.sessionManager.admitted()
		checkCount := m.sessionManager.count()
		select {
		case <-m.done.Wait():
			// finish() does the cleanup. It has run already, except in a
			// dialing worker whose carrier ended: there done is closed at
			// once, and finish() follows when the downlink is drained.
			return
		case <-m.timer.C:
			if m.sessionManager.closeIfIdle(checkSize, checkCount) {
				m.finish()
			}
		}
	}
}

func writeFirstPayload(reader buf.Reader, writer *Writer) error {
	err := buf.CopyOnceTimeout(reader, writer, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return writer.WriteMultiBuffer(buf.MultiBuffer{})
	}

	if err != nil {
		return err
	}

	return nil
}

func (m *ClientWorker) fetchInput(ctx context.Context, s *Session) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	transferType := protocol.TransferTypeStream
	if ob.Target.Network == net.Network_UDP {
		transferType = protocol.TransferTypePacket
	}
	s.transferType = transferType
	var inbound *session.Inbound
	if session.IsReverseMuxFromContext(ctx) {
		inbound = session.InboundFromContext(ctx)
	}
	writer := NewWriter(s.ID, ob.Target, m.link.Writer, transferType, xudp.GetGlobalID(ctx), inbound)
	// The end of an upload ends its session, and with it the reply. Not on
	// a closed worker when the upload ran to its end: the carrier may be
	// gone while fetchOutput is still delivering what it wrote for this
	// session, and finish() closes the session after that. A session whose
	// upload fails to be read is closed here: its application went away.
	replyMayFollow := false
	defer func() {
		if !replyMayFollow || !m.Closed() {
			s.Close(false)
		}
	}()
	defer writer.Close()

	errors.LogInfo(ctx, "dispatching request to ", ob.Target)
	err := writeFirstPayload(s.input, writer)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to write first payload")
		writer.hasError = true
		if !writer.opened {
			return
		}
		// A first payload goes out in as many frames as it needs. The
		// carrier took the one that opens the session, and may have
		// answered it, before the uplink refused the rest.
	} else if err = buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to fetch all input")
		writer.hasError = true
	}
	if err != nil && m.Closed() {
		// The upload stopped on a closed worker. When the uplink refused
		// it, the carrier is gone and nothing takes what the application
		// still sends; its input is read to its end all the same. Left
		// unread it fills and holds an application that sends before it
		// reads its reply, and an application that goes away is not seen.
		// When the input itself failed, it fails again here.
		err = buf.Copy(s.input, buf.Discard)
	}
	replyMayFollow = err == nil
}

func (m *ClientWorker) IsClosing() bool {
	sm := m.sessionManager
	if m.strategy.MaxConnection > 0 && sm.count() >= int(m.strategy.MaxConnection) {
		return true
	}
	return false
}

// IsFull returns true if this ClientWorker is unable to accept more connections.
// it might be because it is closing, or the number of connections has reached the limit.
func (m *ClientWorker) IsFull() bool {
	if m.IsClosing() || m.Closed() {
		return true
	}

	sm := m.sessionManager
	if m.strategy.MaxConcurrency > 0 && sm.admitted() >= int(m.strategy.MaxConcurrency) {
		return true
	}
	return false
}

func (m *ClientWorker) Dispatch(ctx context.Context, link *transport.Link) bool {
	return m.dispatch(ctx, link, false)
}

// DispatchRVS commits one reverse data session with the carrier scope.
func (m *ClientWorker) DispatchRVS(ctx context.Context, link *transport.Link) bool {
	return m.dispatch(ctx, link, true)
}

func (m *ClientWorker) dispatch(ctx context.Context, link *transport.Link, rvs bool) bool {
	if m.IsFull() {
		return false
	}

	sm := m.sessionManager
	admission := sm.allocate(&m.strategy)
	if admission == nil {
		return false
	}
	streamCtx, cancel := context.WithCancel(ctx)
	reservation := session.PresenceScope{}.Prepare()
	if rvs {
		streamCtx = session.ContextWithPresenceMode(streamCtx, session.PresenceModeExternal)
		reservation = m.presence.Prepare()
	}
	if !admission.prepare(cancel) || !admission.beginCommit() {
		cancel()
		reservation.Abort()
		admission.abort()
		return false
	}
	s := &Session{input: link.Reader, output: link.Writer, done: done.New()}
	lease := session.PresenceLease(nil)
	if rvs {
		lease = reservation.Activate()
	}
	if !admission.finishCommit(s, lease) {
		return false
	}
	admission.completeCommit()
	context.AfterFunc(streamCtx, func() { _ = s.Close(false) })
	go m.fetchInput(streamCtx, s)
	if _, ok := link.Reader.(*pipe.Reader); !ok {
		select {
		case <-ctx.Done():
		case <-s.done.Wait():
		}
	}
	return true
}

func (m *ClientWorker) handleStatueKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusNew(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := m.sessionManager.active(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, m.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)
	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (m *ClientWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := m.sessionManager.active(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) fetchOutput() {
	defer m.finish()

	reader := &buf.BufferedReader{Reader: m.link.Reader}

	var meta FrameMetadata
	for {
		err := meta.Unmarshal(reader, false)
		if err != nil {
			if errors.Cause(err) != io.EOF {
				errors.LogInfoInner(context.Background(), err, "failed to read metadata")
			}
			break
		}

		switch meta.SessionStatus {
		case SessionStatusKeepAlive:
			err = m.handleStatueKeepAlive(&meta, reader)
		case SessionStatusEnd:
			err = m.handleStatusEnd(&meta, reader)
		case SessionStatusNew:
			err = m.handleStatusNew(&meta, reader)
		case SessionStatusKeep:
			err = m.handleStatusKeep(&meta, reader)
		default:
			status := meta.SessionStatus
			errors.LogError(context.Background(), "unknown status: ", status)
			return
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to process data")
			return
		}
	}
}

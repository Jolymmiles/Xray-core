package mux

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/singmux"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
	smux       *singmux.Service
	runtime    *Runtime
}

func newServer(dispatcher routing.Dispatcher) *Server {
	return &Server{
		dispatcher: dispatcher,
		smux:       singmux.NewService(dispatcher),
		runtime:    newRuntime(),
	}
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		*s = *newServer(d)
	})
	return s
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

// PresenceProvider exposes the authenticated dispatcher provider to inbound
// proxies that dispatch through the mux server.
func (s *Server) PresenceProvider() session.PresenceProvider {
	if source, ok := s.dispatcher.(session.PresenceProviderSource); ok {
		return source.PresenceProvider()
	}
	return nil
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if singmux.IsDestination(dest) {
		return s.dispatchSMUX(ctx), nil
	}
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	_, err := newServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}, s.runtime, false)
	if err != nil {
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func (s *Server) dispatchSMUX(ctx context.Context) *transport.Link {
	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)
	conn := cnc.NewConnection(
		cnc.ConnectionInputMulti(downlinkWriter),
		cnc.ConnectionOutputMulti(uplinkReader),
	)
	go func() {
		defer conn.Close()
		if err := s.smux.NewConnection(ctx, conn); err != nil && errors.Cause(err) != io.EOF {
			errors.LogInfoInner(ctx, err, "failed to handle SMUX connection")
		}
	}()
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if singmux.IsDestination(dest) {
		conn := cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		)
		defer conn.Close()
		return s.smux.NewConnection(ctx, conn)
	}
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	worker, err := newServerWorker(ctx, s.dispatcher, link, s.runtime, false)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		// Ensure Interrupt completes before return so callers (e.g. VLESS)
		// cannot Release pooled link readers while finish is still running.
		_ = worker.Close()
	case <-worker.WaitClosed():
	}
	return nil
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	return s.runtime.Close()
}

type ServerWorker struct {
	dispatcher     routing.Dispatcher
	link           *transport.Link
	sessionManager *sessionRegistry
	presence       session.PresenceScope
	runtime        *Runtime
	workerToken    uint64
	ownRuntime     bool
	responseSink   *xudpResponseSink
	done           *done.Instance
	timer          *time.Ticker
	finishOnce     sync.Once
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	return newServerWorker(ctx, d, link, newRuntime(), true)
}

func newServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link, runtime *Runtime, ownRuntime bool) (*ServerWorker, error) {
	presence := session.PresenceScope{}
	if source, ok := d.(session.PresenceProviderSource); ok && source.PresenceProvider() != nil {
		presence = source.PresenceProvider().SnapshotPresence(ctx)
	}
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: newSessionRegistry(),
		presence:       presence,
		runtime:        runtime,
		workerToken:    runtime.workerToken(),
		ownRuntime:     ownRuntime,
		done:           done.New(),
		timer:          time.NewTicker(60 * time.Second),
	}
	worker.responseSink = runtime.newResponseSink(link.Writer)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	go worker.run(ctx)
	go worker.monitor()
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}

	writer.Close()
	s.Close(false)
}

// finish tears down sessions and the carrier link, then signals done.
//
// Root cause (#5110 race + pooled VLESS readers): done used to mean "run
// exited" while monitor still Interrupted the link afterward. Callers waiting
// on done (DispatchLink) then Release()'d pooled link.Reader under that
// Interrupt. Contract now: done/WaitClosed ⇒ link is no longer touched.
func (w *ServerWorker) finish() {
	w.finishOnce.Do(func() {
		w.sessionManager.close()
		w.responseSink.close()
		common.Interrupt(w.link.Writer)
		common.Interrupt(w.link.Reader)
		if w.ownRuntime {
			_ = w.runtime.Close()
		}
		common.Must(w.done.Close())
	})
}

func (w *ServerWorker) monitor() {
	defer w.timer.Stop()

	for {
		checkSize := w.sessionManager.admitted()
		checkCount := w.sessionManager.count()
		select {
		case <-w.done.Wait():
			// Cleanup already completed in finish() before done was closed.
			return
		case <-w.timer.C:
			if w.sessionManager.closeIfIdle(checkSize, checkCount) {
				// Unblock run (if still reading) and close only after Interrupt.
				w.finish()
			}
		}
	}
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionManager.activeCount())
}

func (w *ServerWorker) Closed() bool {
	return w.done.Done()
}

func (w *ServerWorker) WaitClosed() <-chan struct{} {
	return w.done.Wait()
}

func (w *ServerWorker) Close() error {
	w.finish()
	return nil
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	ctx = session.SubContextFromMuxInbound(ctx)
	if meta.Inbound != nil && meta.Inbound.Source.IsValid() && meta.Inbound.Local.IsValid() {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			newInbound := *inbound
			newInbound.Source = meta.Inbound.Source
			newInbound.Local = meta.Inbound.Local
			ctx = session.ContextWithInbound(ctx, &newInbound)
		}
	}
	errors.LogInfo(ctx, "received request for ", meta.Target)
	{
		msg := &log.AccessMessage{
			To:     meta.Target,
			Status: log.AccessAccepted,
			Reason: "",
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
			msg.From = inbound.Source
			msg.Email = inbound.User.Email
		}
		ctx = log.ContextWithAccessMessage(ctx, msg)
	}

	if network := session.AllowedNetworkFromContext(ctx); network != net.Network_Unknown {
		if meta.Target.Network != network {
			return errors.New("unexpected network ", meta.Target.Network) // it will break the whole Mux connection
		}
	}
	admission := w.sessionManager.reserve(meta.SessionID)
	if admission == nil {
		if meta.Option.Has(OptionData) {
			_ = buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		_ = closingWriter.Close()
		return nil
	}

	if meta.GlobalID != [8]byte{} { // MUST ignore empty Global ID
		mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
		if err != nil {
			admission.abort()
			return err
		}
		xudpCtx, cancel := context.WithCancel(session.ContextWithTimeoutOnly(ctx, true))
		if !admission.prepare(cancel) {
			cancel()
			admission.abort()
			buf.ReleaseMulti(mb)
			return errors.New("failed to prepare XUDP attachment")
		}
		txCtx, finishTransaction, ok := w.runtime.beginTransaction(xudpCtx)
		if !ok {
			cancel()
			admission.abort()
			buf.ReleaseMulti(mb)
			return errors.New("XUDP runtime is closing")
		}
		defer finishTransaction()
		key := w.runtime.xudpKey(w.presence, w.workerToken, meta.GlobalID)
		flow, err := w.runtime.xudpFlow(txCtx, key, meta.Target, w.dispatcher)
		if err != nil {
			cancel()
			admission.abort()
			buf.ReleaseMulti(mb)
			return errors.New("failed to prepare XUDP flow").Base(err)
		}
		owner, err := flow.attach(admission, w.presence, w.responseSink)
		if err != nil {
			cancel()
			admission.abort()
			buf.ReleaseMulti(mb)
			return errors.New("failed to attach XUDP flow").Base(err)
		}
		// Runtime shutdown joins publication, then closes the flow to unblock any
		// post-commit backend write. The deferred call remains the error-path guard.
		finishTransaction()
		context.AfterFunc(xudpCtx, func() { _ = owner.Close(false) })
		if err := owner.output.WriteMultiBuffer(mb); err != nil {
			_ = owner.Close(false)
			w.runtime.removeFlow(key, flow)
			return errors.New("failed to write initial XUDP payload").Base(err)
		}
		return nil
	}

	streamCtx, cancel := context.WithCancel(session.ContextWithPresenceMode(ctx, session.PresenceModeExternal))
	if !admission.prepare(cancel) {
		cancel()
		admission.abort()
		return errors.New("failed to prepare new session")
	}
	presence := w.presence.Prepare()
	link, err := w.dispatcher.Dispatch(streamCtx, meta.Target)
	if err != nil {
		cancel()
		presence.Abort()
		admission.abort()
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	s := &Session{
		input:        link.Reader,
		output:       link.Writer,
		ID:           meta.SessionID,
		transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if !admission.beginCommit() {
		presence.Abort()
		admission.abort()
		closeRejectedSession(s, nil)
		return errors.New("failed to begin new session")
	}
	lease := presence.Activate()
	if !admission.finishCommit(s, lease) {
		return errors.New("failed to add new session")
	}
	admission.completeCommit()
	context.AfterFunc(streamCtx, func() { _ = s.Close(false) })
	go handle(ctx, s, w.link.Writer)
	if !meta.Option.Has(OptionData) {
		return nil
	}

	rr := s.NewReader(reader, &meta.Target)
	err = buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}
	return err
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionManager.active(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream writer. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (w *ServerWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := w.sessionManager.active(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleFrame(ctx context.Context, reader *buf.BufferedReader) error {
	var meta FrameMetadata
	err := meta.Unmarshal(reader, session.IsReverseMuxFromContext(ctx))
	if err != nil {
		return errors.New("failed to read metadata").Base(err)
	}

	switch meta.SessionStatus {
	case SessionStatusKeepAlive:
		err = w.handleStatusKeepAlive(&meta, reader)
	case SessionStatusEnd:
		err = w.handleStatusEnd(&meta, reader)
	case SessionStatusNew:
		err = w.handleStatusNew(session.ContextWithIsReverseMux(ctx, false), &meta, reader)
	case SessionStatusKeep:
		err = w.handleStatusKeep(&meta, reader)
	default:
		status := meta.SessionStatus
		return errors.New("unknown status: ", status).AtError()
	}

	if err != nil {
		return errors.New("failed to process data").Base(err)
	}
	return nil
}

func (w *ServerWorker) run(ctx context.Context) {
	defer w.finish()

	reader := &buf.BufferedReader{Reader: w.link.Reader}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := w.handleFrame(ctx, reader)
			if err != nil {
				if errors.Cause(err) != io.EOF {
					errors.LogInfoInner(ctx, err, "unexpected EOF")
				}
				return
			}
		}
	}
}

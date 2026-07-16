package mux

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher       routing.Dispatcher
	runtime          *Runtime
	presenceProvider session.PresenceProvider
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{runtime: NewRuntime()}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
		if source, ok := d.(interface {
			PresenceProvider() session.PresenceProvider
		}); ok {
			s.presenceProvider = source.PresenceProvider()
		}
	})
	return s
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

func (s *Server) PresenceProvider() session.PresenceProvider {
	return s.presenceProvider
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	_, err := newServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}, s.runtime, false, s.presenceProvider, presenceModeForProvider(s.presenceProvider))
	if err != nil {
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	worker, err := newServerWorker(ctx, s.dispatcher, link, s.runtime, false, s.presenceProvider, presenceModeForProvider(s.presenceProvider))
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-worker.done.Wait():
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
	dispatcher      routing.Dispatcher
	link            *transport.Link
	sessionRegistry *ServerSessionRegistry
	done            *done.Instance
	runDone         *done.Instance
	drained         *done.Instance
	timer           *time.Ticker
	runtime         *Runtime
	ownedRuntime    bool
	presenceMode    session.PresenceMode
	presenceScope   session.PresenceScope
	cancel          context.CancelFunc
}

type ServerWorkerOptions struct {
	Runtime          *Runtime
	PresenceProvider session.PresenceProvider
	PresenceMode     session.PresenceMode
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	return NewServerWorkerWithOptions(ctx, d, link, ServerWorkerOptions{PresenceMode: session.PresenceModeLegacy})
}

func NewServerWorkerWithOptions(ctx context.Context, d routing.Dispatcher, link *transport.Link, options ServerWorkerOptions) (*ServerWorker, error) {
	runtime := options.Runtime
	ownedRuntime := false
	if runtime == nil {
		runtime = NewRuntime()
		ownedRuntime = true
	}
	return newServerWorker(ctx, d, link, runtime, ownedRuntime, options.PresenceProvider, options.PresenceMode)
}

func presenceModeForProvider(provider session.PresenceProvider) session.PresenceMode {
	if provider == nil {
		return session.PresenceModeLegacy
	}
	return session.PresenceModeStructural
}

func newServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link, runtime *Runtime, ownedRuntime bool, provider session.PresenceProvider, presenceMode session.PresenceMode) (*ServerWorker, error) {
	if runtime == nil {
		return nil, errors.New("nil mux runtime")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &ServerWorker{
		dispatcher:      d,
		link:            link,
		sessionRegistry: NewServerSessionRegistry(),
		done:            done.New(),
		runDone:         done.New(),
		drained:         done.New(),
		timer:           time.NewTicker(60 * time.Second),
		runtime:         runtime,
		ownedRuntime:    ownedRuntime,
		presenceMode:    presenceMode,
		cancel:          cancel,
	}
	if presenceMode == session.PresenceModeStructural && provider != nil {
		worker.presenceScope = provider.SnapshotPresence(ctx)
	}
	if !runtime.registerWorker(worker) {
		cancel()
		worker.timer.Stop()
		return nil, errors.New("mux runtime is closing")
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.CanSpliceCopy = 3
	}
	go worker.run(workerCtx)
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

func (w *ServerWorker) monitor() {
	defer w.timer.Stop()
	defer func() {
		w.runtime.unregisterWorker(w)
		common.Must(w.drained.Close())
		if w.ownedRuntime {
			_ = w.runtime.Close()
		}
	}()

	for {
		checkSize := w.sessionRegistry.Size()
		checkCount := w.sessionRegistry.Count()
		select {
		case <-w.done.Wait():
			w.cancel()
			w.sessionRegistry.Close()
			common.Interrupt(w.link.Writer)
			common.Interrupt(w.link.Reader)
			<-w.runDone.Wait()
			return
		case <-w.timer.C:
			if w.sessionRegistry.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				common.Must(w.done.Close())
			}
		}
	}
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionRegistry.Size())
}

func (w *ServerWorker) Closed() bool {
	return w.done.Done()
}

func (w *ServerWorker) WaitClosed() <-chan struct{} {
	return w.drained.Wait()
}

func (w *ServerWorker) Close() error {
	w.cancel()
	return w.done.Close()
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	reservation, reserved := w.sessionRegistry.Reserve(meta.SessionID)
	if !reserved {
		return errors.New("duplicate or closed session ID ", meta.SessionID)
	}
	published := false
	presenceCommitted := false
	presenceReservation := session.NoopPresenceReservation()
	if w.presenceMode == session.PresenceModeStructural {
		presenceReservation = w.presenceScope.Prepare()
	}
	defer func() {
		if !published {
			reservation.Abort()
		}
		if !presenceCommitted {
			presenceReservation.Abort()
		}
	}()
	ctx = session.SubContextFromMuxInbound(ctx)
	ctx = session.ContextWithPresenceMode(ctx, w.presenceMode)
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

	if meta.GlobalID != [8]byte{} { // MUST ignore empty Global ID
		var err error
		published, presenceCommitted, err = w.handleXUDPStatusNew(ctx, meta, reader, reservation, presenceReservation)
		return err
	}

	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	if !reservation.BeginCommit() {
		_ = common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return errors.New("session reservation closed before commit")
	}
	s := &Session{
		input:         link.Reader,
		output:        link.Writer,
		ID:            meta.SessionID,
		transferType:  protocol.TransferTypeStream,
		presenceLease: presenceReservation.Activate(),
	}
	presenceCommitted = true
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if !reservation.Publish(s) {
		s.Close(false)
		return errors.New("failed to publish new session")
	}
	published = true
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

func (w *ServerWorker) handleXUDPStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader, reservation *ServerSessionReservation, presenceReservation session.PresenceReservation) (bool, bool, error) {
	payload, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
	if err != nil {
		return false, false, err
	}
	key := w.runtime.xudpKey(w.presenceScope, w.presenceMode, meta.GlobalID)
	w.runtime.xudpMu.Lock()
	flow := w.runtime.xudp[key]
	created := flow == nil
	if created {
		flow = newXUDPFlow(w.runtime, meta.GlobalID)
		flow.Target = meta.Target
		flow.Status = Initializing
		flow.Preparing = true
		w.runtime.xudp[key] = flow
	} else {
		if flow.Preparing {
			w.runtime.xudpMu.Unlock()
			buf.ReleaseMulti(payload)
			return false, false, errors.New("XUDP rebind already preparing")
		}
		if flow.Target.String() != meta.Target.String() {
			w.runtime.xudpMu.Unlock()
			buf.ReleaseMulti(payload)
			return false, false, errors.New("XUDP target mismatch")
		}
		flow.Preparing = true
		flow.Status = Initializing
	}
	oldAttachment := flow.Attachment
	w.runtime.xudpMu.Unlock()

	if created {
		dispatchCtx := session.ContextWithTimeoutOnly(ctx, true)
		link, dispatchErr := w.dispatcher.Dispatch(dispatchCtx, meta.Target)
		if dispatchErr != nil {
			w.abortXUDPPreparation(key, flow, true)
			buf.ReleaseMulti(payload)
			return false, false, errors.New("XUDP new ", meta.GlobalID).Base(errors.New("failed to dispatch request to ", meta.Target).Base(dispatchErr))
		}
		if !flow.setBackend(link.Reader, link.Writer) {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			_ = common.Close(link.Writer)
			w.abortXUDPPreparation(key, flow, true)
			buf.ReleaseMulti(payload)
			return false, false, errors.New("XUDP runtime closed during backend dispatch")
		}
		flow.startPumps()
	} else {
		if flow.Output == nil {
			w.abortXUDPPreparation(key, flow, false)
			buf.ReleaseMulti(payload)
			return false, false, errors.New("XUDP backend has no writer")
		}
	}

	if !reservation.BeginCommit() {
		w.abortXUDPPreparation(key, flow, created)
		if created {
			flow.Interrupt()
		}
		buf.ReleaseMulti(payload)
		return false, false, errors.New("session reservation closed before XUDP commit")
	}

	var lease session.PresenceLease
	if oldAttachment != nil {
		lease = presenceReservation.Handoff(oldAttachment.presenceLease)
	} else {
		lease = presenceReservation.Activate()
	}
	attachmentReader, attachmentWriter := pipe.New(pipe.WithSizeLimit(1024 * 1024))
	newAttachment := &Session{
		input:         attachmentReader,
		ID:            meta.SessionID,
		transferType:  protocol.TransferTypePacket,
		XUDP:          flow,
		runtime:       w.runtime,
		xudpSink:      attachmentWriter,
		presenceLease: lease,
	}

	w.runtime.xudpMu.Lock()
	if w.runtime.xudp[key] != flow || !flow.Preparing || flow.Attachment != oldAttachment {
		w.runtime.xudpMu.Unlock()
		newAttachment.Close(false)
		buf.ReleaseMulti(payload)
		return false, true, errors.New("stale XUDP commit")
	}
	flow.Generation++
	newAttachment.xudpGeneration = flow.Generation
	newAttachment.output = &xudpAttachmentWriter{flow: flow, generation: flow.Generation}
	flow.Attachment = newAttachment
	flow.Status = Active
	flow.Preparing = false
	w.runtime.xudpMu.Unlock()

	if !reservation.Publish(newAttachment) {
		newAttachment.Close(false)
		if oldAttachment != nil {
			oldAttachment.Close(false)
		}
		buf.ReleaseMulti(payload)
		return false, true, errors.New("failed to publish XUDP attachment")
	}
	if oldAttachment != nil {
		oldAttachment.Close(false)
	}
	if newAttachment.Closed() {
		buf.ReleaseMulti(payload)
		return true, true, nil
	}
	if writeErr := newAttachment.output.WriteMultiBuffer(payload); writeErr != nil {
		newAttachment.Close(false)
		flow.Interrupt()
		return true, true, errors.New("failed to write committed XUDP payload").Base(writeErr)
	}
	go handle(ctx, newAttachment, w.link.Writer)
	return true, true, nil
}

func (w *ServerWorker) abortXUDPPreparation(key xudpKey, flow *XUDP, created bool) {
	w.runtime.xudpMu.Lock()
	defer w.runtime.xudpMu.Unlock()
	if w.runtime.xudp[key] != flow {
		return
	}
	if created {
		delete(w.runtime.xudp, key)
		return
	}
	flow.Preparing = false
	if flow.Attachment == nil {
		flow.Status = Expiring
	} else {
		flow.Status = Active
	}
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionRegistry.Get(meta.SessionID)
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
	if s, found := w.sessionRegistry.Get(meta.SessionID); found {
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
	defer func() {
		common.Must(w.done.Close())
	}()
	defer func() { common.Must(w.runDone.Close()) }()

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

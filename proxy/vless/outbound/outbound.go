package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre  uint32
	initpre  sync.Once
	preConns chan *ConnExpire
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

func shouldUseTestpre(brutal bool, testpre uint32, reverse *Reverse) bool {
	return testpre > 0 && reverse == nil && !brutal
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		rvsCtx := session.ContextWithInbound(ctx, &session.Inbound{
			Tag:  a.Reverse.Tag,
			Name: "vless-reverse",
			User: handler.server.User, // TODO: email
		})
		if sc := a.Reverse.Sniffing; sc != nil && sc.Enabled {
			request, err := proxymanConfig.BuildSniffingRequest(sc)
			if err != nil {
				return nil, errors.New("failed to build reverse sniffing request").Base(err).AtError()
			}
			rvsCtx = session.ContextWithContent(rvsCtx, &session.Content{
				SniffingRequest: request,
			})
		}
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx:        rvsCtx,
			handler:    handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		handler.reverse.scheduleStart(2 * time.Second)
	}

	handler.testpre = a.Testpre

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.preConns != nil {
		close(h.preConns)
	}
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	if shouldUseTestpre(proxyman.IsSMUXBrutalCarrier(ctx), h.testpre, h.reverse) {
		h.initpre.Do(func() {
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				go func() {
					defer func() { recover() }()
					ctx := xctx.ContextWithID(context.Background(), session.NewID())
					for {
						conn, err := dialer.Dial(ctx, rec.Destination)
						if err != nil {
							errors.LogWarningInner(ctx, err, "pre-connect failed")
							continue
						}
						h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)} // TODO: customize & randomize
						time.Sleep(time.Millisecond * 200)                                             // TODO: customize & randomize
					}
				}()
			}
		})
		for {
			connTime := <-h.preConns
			if connTime == nil {
				return errors.New("closed handler").AtWarning()
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	ob.Conn = conn // for Vision's pre-connect

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	var visionCarrier proxy.VisionCarrier
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		if request.Command == protocol.RequestCommandUDP && !allowUDP443 && request.Port == 443 {
			return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
		}
		visionCarrier = proxy.ResolveOutboundVisionCarrier(conn, iConn)
		switch request.Command {
		case protocol.RequestCommandUDP:
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			if !visionCarrier.Supported() {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			if !visionCarrier.CanSpliceCopy() {
				ob.CanSpliceCopy = 3
			}
			var ok bool
			input, rawInput, ok = visionCarrier.Buffers()
			if !ok {
				return errors.New("XTLS failed to access TLS input buffers").AtWarning()
			}
		default:
			panic("unknown VLESS request command")
		}
	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := encoding.NewTrafficStateForFlow(account.ID.Bytes(), requestAddons.Flow)
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		bufferWriter.SetFlushNext()
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if version, invalid := visionCarrier.InvalidTLSVersion(); invalid {
				return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, version).AtWarning()
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	postRequestAndCloseWrite := task.OnSuccess(postRequest, func() error {
		if trafficState != nil && trafficState.Outbound.UplinkWriterDirectCopyActive.Load() {
			rawConn, _, _ := proxy.UnwrapRawConn(conn)
			return stat.TryCloseWrite(rawConn)
		}
		return stat.TryCloseWrite(conn)
	})
	if err := task.Run(ctx, postRequestAndCloseWrite, task.OnSuccessClose(getResponse, clientWriter)); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	mu           sync.Mutex
	tag          string
	dispatcher   routing.Dispatcher
	ctx          context.Context
	handler      *Handler
	workers      []*reverse.BridgeWorker
	monitorTask  *task.Periodic
	closed       bool
	startTimer   *time.Timer
	delayedStart sync.WaitGroup
	starts       sync.WaitGroup
	closeOnce    sync.Once
	workersDone  sync.WaitGroup
}

func (r *Reverse) monitor() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	workers := append([]*reverse.BridgeWorker(nil), r.workers...)
	r.mu.Unlock()
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		} else if w.Closed() {
			_ = w.Close()
		}
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range activeWorkers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return w.Close()
		}
		activeWorkers = append(activeWorkers, w)
		r.workers = activeWorkers
		r.workersDone.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workersDone.Done()
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.workers = activeWorkers
	}
	r.mu.Unlock()
	return nil
}

func (r *Reverse) scheduleStart(delay time.Duration) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.delayedStart.Add(1)
	r.startTimer = time.AfterFunc(delay, func() {
		defer r.delayedStart.Done()
		_ = r.Start()
	})
	r.mu.Unlock()
}

func (r *Reverse) Start() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("VLESS reverse owner is closing")
	}
	r.starts.Add(1)
	r.mu.Unlock()
	defer r.starts.Done()
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	var result error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		workers := r.workers
		r.workers = nil
		startTimer := r.startTimer
		r.startTimer = nil
		r.mu.Unlock()
		if startTimer != nil && startTimer.Stop() {
			r.delayedStart.Done()
		}
		r.delayedStart.Wait()
		r.starts.Wait()
		result = r.monitorTask.Close()
		for _, worker := range workers {
			result = errors.Combine(result, worker.Close())
		}
		r.workersDone.Wait()
	})
	return result
}

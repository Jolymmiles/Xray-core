package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/extension"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var dc dns.Client
		if err := core.RequireFeatures(ctx, func(d dns.Client) error {
			dc = d
			return nil
		}); err != nil {
			return nil, err
		}

		c := config.(*Config)

		validator := new(vless.MemoryValidator)
		for _, user := range c.Users {
			u, err := user.ToMemoryUser()
			if err != nil {
				return nil, errors.New("failed to get VLESS user").Base(err).AtError()
			}
			if err := validator.Add(u); err != nil {
				return nil, errors.New("failed to initiate user").Base(err).AtError()
			}
		}
		validator.Warmup()

		return New(ctx, c, dc, validator)
	}))
}

// Handler is an inbound connection handler that handles messages in VLess protocol.
type Handler struct {
	inboundHandlerManager  feature_inbound.Manager
	policyManager          policy.Manager
	sessionPolicy          policy.Session
	stats                  stats.Manager
	validator              vless.Validator
	decryption             *encryption.ServerInstance
	outboundHandlerManager outbound.Manager
	observer               features.Feature
	defaultDispatcher      routing.Dispatcher
	ctx                    context.Context
	reverseLifecycleMu     sync.Mutex
	reverseClosed          bool
	reverseClosing         chan struct{}
	reverseCalls           sync.WaitGroup
	closeOnce              sync.Once
	closeErr               error
	fallbacks              map[string]map[string]map[string]*Fallback // or nil
	// regexps               map[string]*regexp.Regexp       // or nil
}

func logFirstBufferLength(ctx context.Context, length int64) {
	if log.ShouldLog(log.Severity_Info) {
		errors.LogInfo(ctx, "firstLen = ", length)
	}
}

func logReceivedRequest(ctx context.Context, request *protocol.RequestHeader) {
	if log.ShouldLog(log.Severity_Info) {
		errors.LogInfo(ctx, "received request for ", request.Destination())
	}
}

// New creates a new VLess inbound handler.
func New(ctx context.Context, config *Config, dc dns.Client, validator vless.Validator) (*Handler, error) {
	v := core.MustFromContext(ctx)
	policyManager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	handler := &Handler{
		inboundHandlerManager:  v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		policyManager:          policyManager,
		sessionPolicy:          policyManager.ForLevel(0),
		stats:                  v.GetFeature(stats.ManagerType()).(stats.Manager),
		validator:              validator,
		outboundHandlerManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		observer:               v.GetFeature(extension.ObservatoryType()),
		defaultDispatcher:      v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:                    ctx,
	}

	if config.Decryption != "" && config.Decryption != "none" {
		s := strings.Split(config.Decryption, ".")
		var nfsSKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsSKeysBytes = append(nfsSKeysBytes, b)
		}
		handler.decryption = &encryption.ServerInstance{}
		if err := handler.decryption.Init(nfsSKeysBytes, config.XorMode, config.SecondsFrom, config.SecondsTo, config.Padding); err != nil {
			return nil, errors.New("failed to use decryption").Base(err).AtError()
		}
	}

	if config.Fallbacks != nil {
		handler.fallbacks = make(map[string]map[string]map[string]*Fallback)
		// handler.regexps = make(map[string]*regexp.Regexp)
		for _, fb := range config.Fallbacks {
			if handler.fallbacks[fb.Name] == nil {
				handler.fallbacks[fb.Name] = make(map[string]map[string]*Fallback)
			}
			if handler.fallbacks[fb.Name][fb.Alpn] == nil {
				handler.fallbacks[fb.Name][fb.Alpn] = make(map[string]*Fallback)
			}
			handler.fallbacks[fb.Name][fb.Alpn][fb.Path] = fb
			/*
				if fb.Path != "" {
					if r, err := regexp.Compile(fb.Path); err != nil {
						return nil, errors.New("invalid path regexp").Base(err).AtError()
					} else {
						handler.regexps[fb.Path] = r
					}
				}
			*/
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn := range handler.fallbacks[""] {
						if apfb[alpn] == nil {
							apfb[alpn] = make(map[string]*Fallback)
						}
					}
				}
			}
		}
		for _, apfb := range handler.fallbacks {
			if apfb[""] != nil {
				for alpn, pfb := range apfb {
					if alpn != "" { // && alpn != "h2" {
						for path, fb := range apfb[""] {
							if pfb[path] == nil {
								pfb[path] = fb
							}
						}
					}
				}
			}
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn, pfb := range handler.fallbacks[""] {
						for path, fb := range pfb {
							if apfb[alpn][path] == nil {
								apfb[alpn][path] = fb
							}
						}
					}
				}
			}
		}
	}

	return handler, nil
}

func isMuxAndNotXUDP(request *protocol.RequestHeader, first *buf.Buffer) bool {
	if request.Command != protocol.RequestCommandMux {
		return false
	}
	if first.Len() < 7 {
		return true
	}
	firstBytes := first.Bytes()
	return !(firstBytes[2] == 0 && // ID high
		firstBytes[3] == 0 && // ID low
		firstBytes[6] == 2) // Network type: UDP
}

func (h *Handler) GetReverse(a *vless.MemoryAccount) (*Reverse, error) {
	h.reverseLifecycleMu.Lock()
	if h.reverseClosed {
		h.reverseLifecycleMu.Unlock()
		return nil, errors.New("VLESS inbound reverse owner is closing")
	}
	if h.reverseClosing == nil {
		h.reverseClosing = make(chan struct{})
	}
	reverseClosing := h.reverseClosing
	h.reverseCalls.Add(1)
	h.reverseLifecycleMu.Unlock()
	defer h.reverseCalls.Done()

	u := h.validator.Get(a.ID.UUID())
	if u == nil {
		return nil, errors.New("reverse: user " + a.ID.String() + " doesn't exist anymore")
	}
	a = u.Account.(*vless.MemoryAccount)
	if a.Reverse == nil || a.Reverse.Tag == "" {
		return nil, errors.New("reverse: user " + a.ID.String() + " is not allowed to create reverse proxy")
	}
	r := h.outboundHandlerManager.GetHandler(a.Reverse.Tag)
	if r == nil {
		picker, _ := reverse.NewStaticMuxPicker()
		r = &Reverse{tag: a.Reverse.Tag, picker: picker, client: &mux.ClientManager{Picker: picker}}
		for len(h.outboundHandlerManager.ListHandlers(h.ctx)) == 0 {
			timer := time.NewTimer(time.Second)
			select {
			case <-reverseClosing:
				if !timer.Stop() {
					<-timer.C
				}
				_ = r.Close()
				return nil, errors.New("VLESS inbound reverse owner is closing")
			case <-timer.C:
			}
		}
		if err := h.outboundHandlerManager.AddHandler(h.ctx, r); err != nil {
			_ = r.Close()
			return nil, err
		}
	}
	if r, ok := r.(*Reverse); ok {
		return r, nil
	}
	return nil, errors.New("reverse: outbound " + a.Reverse.Tag + " is not type Reverse")
}

func (h *Handler) RemoveReverse(u *protocol.MemoryUser) {
	if u != nil {
		a := u.Account.(*vless.MemoryAccount)
		if a.Reverse != nil && a.Reverse.Tag != "" {
			if handler := h.outboundHandlerManager.GetHandler(a.Reverse.Tag); handler != nil {
				_ = handler.Close()
			}
			h.outboundHandlerManager.RemoveHandler(h.ctx, a.Reverse.Tag)
		}
	}
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		h.reverseLifecycleMu.Lock()
		h.reverseClosed = true
		if h.reverseClosing == nil {
			h.reverseClosing = make(chan struct{})
		}
		close(h.reverseClosing)
		h.reverseLifecycleMu.Unlock()
		h.reverseCalls.Wait()
		if h.decryption != nil {
			h.decryption.Close()
		}
		for _, u := range h.validator.GetAll() {
			h.RemoveReverse(u)
		}
		h.closeErr = errors.Combine(common.Close(h.validator))
	})
	return h.closeErr
}

// AddUser implements proxy.UserManager.AddUser().
func (h *Handler) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return h.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (h *Handler) RemoveUser(ctx context.Context, e string) error {
	h.RemoveReverse(h.validator.GetByEmail(e))
	return h.validator.Del(e)
}

// GetUser implements proxy.UserManager.GetUser().
func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return h.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.GetUsers().
func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return h.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (h *Handler) GetUsersCount(context.Context) int64 {
	return h.validator.GetCount()
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatch routing.Dispatcher) error {
	iConn := stat.TryUnwrapStatsConn(connection)

	if h.decryption != nil {
		var err error
		if connection, err = h.decryption.Handshake(connection, nil); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	sessionPolicy := h.sessionPolicy
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	first := buf.New()
	firstLen, errR := first.ReadFrom(connection)
	if errR != nil {
		first.Release()
		return errR
	}
	logFirstBufferLength(ctx, firstLen)

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(connection),
		Buffer: buf.MultiBuffer{first},
	}
	defer func() {
		reader.Buffer = buf.ReleaseMulti(reader.Buffer)
	}()

	var userSentID [16]byte // not MemoryAccount.ID
	var request *protocol.RequestHeader
	var requestAddons encoding.HeaderAddons
	var err error

	napfb := h.fallbacks
	fallbackEnabled := napfb != nil
	isfb := fallbackEnabled

	if fallbackEnabled && firstLen < 18 {
		err = errors.New("fallback directly")
	} else {
		userSentID, request, requestAddons, isfb, err = encoding.DecodeRequestHeaderFromFirst(first, reader, h.validator, fallbackEnabled)
	}

	if err != nil {
		if isfb {
			if err := connection.SetReadDeadline(time.Time{}); err != nil {
				errors.LogWarningInner(ctx, err, "unable to set back read deadline")
			}
			errors.LogInfoInner(ctx, err, "fallback starts")

			name := ""
			alpn := ""
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				cs := tlsConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				if log.ShouldLog(log.Severity_Info) {
					errors.LogInfo(ctx, "realName = "+name)
					errors.LogInfo(ctx, "realAlpn = "+alpn)
				}
			} else if realityConn, ok := iConn.(*reality.Conn); ok {
				cs := realityConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				if log.ShouldLog(log.Severity_Info) {
					errors.LogInfo(ctx, "realName = "+name)
					errors.LogInfo(ctx, "realAlpn = "+alpn)
				}
			}
			name = strings.ToLower(name)
			alpn = strings.ToLower(alpn)

			if len(napfb) > 1 || napfb[""] == nil {
				if name != "" && napfb[name] == nil {
					match := ""
					for n := range napfb {
						if n != "" && strings.Contains(name, n) && len(n) > len(match) {
							match = n
						}
					}
					name = match
				}
			}

			if napfb[name] == nil {
				name = ""
			}
			apfb := napfb[name]
			if apfb == nil {
				return errors.New(`failed to find the default "name" config`).AtWarning()
			}

			if apfb[alpn] == nil {
				alpn = ""
			}
			pfb := apfb[alpn]
			if pfb == nil {
				return errors.New(`failed to find the default "alpn" config`).AtWarning()
			}

			path := ""
			if len(pfb) > 1 || pfb[""] == nil {
				/*
					if lines := bytes.Split(firstBytes, []byte{'\r', '\n'}); len(lines) > 1 {
						if s := bytes.Split(lines[0], []byte{' '}); len(s) == 3 {
							if len(s[0]) < 8 && len(s[1]) > 0 && len(s[2]) == 8 {
								errors.New("realPath = " + string(s[1])).AtInfo().WriteToLog(sid)
								for _, fb := range pfb {
									if fb.Path != "" && h.regexps[fb.Path].Match(s[1]) {
										path = fb.Path
										break
									}
								}
							}
						}
					}
				*/
				if firstLen >= 18 && first.Byte(4) != '*' { // not h2c
					firstBytes := first.Bytes()
					for i := 4; i <= 8; i++ { // 5 -> 9
						if firstBytes[i] == '/' && firstBytes[i-1] == ' ' {
							search := len(firstBytes)
							if search > 64 {
								search = 64 // up to about 60
							}
							for j := i + 1; j < search; j++ {
								k := firstBytes[j]
								if k == '\r' || k == '\n' { // avoid logging \r or \n
									break
								}
								if k == '?' || k == ' ' {
									path = string(firstBytes[i:j])
									if log.ShouldLog(log.Severity_Info) {
										errors.LogInfo(ctx, "realPath = "+path)
									}
									if pfb[path] == nil {
										path = ""
									}
									break
								}
							}
							break
						}
					}
				}
			}
			fb := pfb[path]
			if fb == nil {
				return errors.New(`failed to find the default "path" config`).AtWarning()
			}

			ctx, cancel := context.WithCancel(ctx)
			timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
			ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

			var conn net.Conn
			if err := retry.ExponentialBackoff(5, 100).On(func() error {
				var dialer net.Dialer
				conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
				if err != nil {
					return err
				}
				return nil
			}); err != nil {
				return errors.New("failed to dial to " + fb.Dest).Base(err).AtWarning()
			}
			defer conn.Close()

			serverReader := buf.NewReader(conn)
			serverWriter := buf.NewWriter(conn)

			postRequest := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
				if fb.Xver != 0 {
					ipType := 4
					remoteAddr, remotePort, err := net.SplitHostPort(connection.RemoteAddr().String())
					if err != nil {
						ipType = 0
					}
					localAddr, localPort, err := net.SplitHostPort(connection.LocalAddr().String())
					if err != nil {
						ipType = 0
					}
					if ipType == 4 {
						for i := 0; i < len(remoteAddr); i++ {
							if remoteAddr[i] == ':' {
								ipType = 6
								break
							}
						}
					}
					pro := buf.New()
					defer pro.Release()
					switch fb.Xver {
					case 1:
						if ipType == 0 {
							pro.Write([]byte("PROXY UNKNOWN\r\n"))
							break
						}
						if ipType == 4 {
							pro.Write([]byte("PROXY TCP4 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						} else {
							pro.Write([]byte("PROXY TCP6 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						}
					case 2:
						pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")) // signature
						if ipType == 0 {
							pro.Write([]byte("\x20\x00\x00\x00")) // v2 + LOCAL + UNSPEC + UNSPEC + 0 bytes
							break
						}
						if ipType == 4 {
							pro.Write([]byte("\x21\x11\x00\x0C")) // v2 + PROXY + AF_INET + STREAM + 12 bytes
							pro.Write(net.ParseIP(remoteAddr).To4())
							pro.Write(net.ParseIP(localAddr).To4())
						} else {
							pro.Write([]byte("\x21\x21\x00\x24")) // v2 + PROXY + AF_INET6 + STREAM + 36 bytes
							pro.Write(net.ParseIP(remoteAddr).To16())
							pro.Write(net.ParseIP(localAddr).To16())
						}
						p1, _ := strconv.ParseUint(remotePort, 10, 16)
						p2, _ := strconv.ParseUint(localPort, 10, 16)
						pro.Write([]byte{byte(p1 >> 8), byte(p1), byte(p2 >> 8), byte(p2)})
					}
					if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro}); err != nil {
						return errors.New("failed to set PROXY protocol v", fb.Xver).Base(err).AtWarning()
					}
				}
				if err := buf.Copy(reader, serverWriter, buf.UpdateActivity(timer)); err != nil {
					return errors.New("failed to fallback request payload").Base(err).AtInfo()
				}
				return nil
			}

			writer := buf.NewWriter(connection)

			getResponse := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
				if err := buf.Copy(serverReader, writer, buf.UpdateActivity(timer)); err != nil {
					return errors.New("failed to deliver response payload").Base(err).AtInfo()
				}
				return nil
			}

			if err := task.Run(ctx, task.OnSuccessClose(postRequest, serverWriter), task.OnSuccessClose(getResponse, writer)); err != nil {
				common.Interrupt(serverReader)
				common.Interrupt(serverWriter)
				return errors.New("fallback ends").Base(err).AtInfo()
			}
			return nil
		}

		if errors.Cause(err) != io.EOF {
			inboundTag := ""
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				inboundTag = inbound.Tag
			}
			log.RecordAccess(ctx, &log.AccessMessage{
				Component: "proxy/vless/inbound",
				From:      connection.RemoteAddr(),
				To:        "",
				Status:    log.AccessRejected,
				Reason:    err,
				Inbound:   inboundTag,
			})
			err = errors.New("invalid request from ", connection.RemoteAddr()).Base(err).AtInfo()
		}
		return err
	}
	defer encoding.ReleaseRequestHeader(request)

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to set back read deadline")
	}
	logReceivedRequest(ctx, request)

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.Name = "vless"
	inbound.User = request.User
	inbound.VlessRoute = net.PortFromBytes(userSentID[6:8])

	account := request.User.Account.(*vless.MemoryAccount)

	if account.Reverse != nil && request.Command != protocol.RequestCommandRvs {
		return forwardProxyNotAllowedError(account.ID)
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	switch requestAddons.Flow {
	case vless.XRV:
		if account.Flow == requestAddons.Flow {
			inbound.CanSpliceCopy = 2
			switch request.Command {
			case protocol.RequestCommandUDP:
				return flowDoesNotSupportUDPError(requestAddons.Flow)
			case protocol.RequestCommandMux, protocol.RequestCommandRvs:
				inbound.CanSpliceCopy = 3
				fallthrough // we will break Mux connections that contain TCP requests
			case protocol.RequestCommandTCP:
				visionCarrier := proxy.ResolveInboundVisionCarrier(connection, iConn)
				if !visionCarrier.Supported() {
					return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
				}
				if !visionCarrier.CanSpliceCopy() {
					inbound.CanSpliceCopy = 3
				}
				if version, invalid := visionCarrier.InvalidTLSVersion(); invalid {
					return invalidOuterTLSVersionError(requestAddons.Flow, version)
				}
				var ok bool
				input, rawInput, ok = visionCarrier.Buffers()
				if !ok {
					return errors.New("XTLS failed to access TLS input buffers").AtWarning()
				}
			}
		} else {
			return accountFlowMismatchError(account.ID, requestAddons.Flow)
		}
	case "":
		inbound.CanSpliceCopy = 3
		if account.Flow == vless.XRV && (request.Command == protocol.RequestCommandTCP || isMuxAndNotXUDP(request, first)) {
			return accountEmptyFlowError(account.ID)
		}
	default:
		return unknownRequestFlowError(requestAddons.Flow)
	}

	if request.Command != protocol.RequestCommandMux {
		from, to := net.FormatAccessEndpoints(inbound.Source, request.Destination())
		ctx = session.ContextWithAccessMessage(ctx, &log.AccessMessage{
			FromString: from,
			ToString:   to,
			Status:     log.AccessAccepted,
			Email:      request.User.Email,
		})
	} else if account.Flow == vless.XRV {
		ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
	}

	vision := requestAddons.Flow == vless.XRV
	trafficState := encoding.NewTrafficStateForVision(userSentID[:], vision)
	clientReader := encoding.DecodeBody(reader, request)
	if vision {
		clientReader = proxy.NewVisionReader(clientReader, trafficState, true, ctx, connection, input, rawInput, nil)
	}

	bufferWriter, err := buf.NewPrefixWriter(buf.NewWriter(connection), []byte{request.Version, 0})
	if err != nil {
		return errors.New("failed to encode response header").Base(err).AtWarning()
	}
	clientWriter := encoding.EncodeBody(bufferWriter, request, vision, trafficState, false, ctx, connection, nil)
	link := &transport.Link{Reader: clientReader, Writer: clientWriter}

	if request.Command == protocol.RequestCommandRvs {
		r, err := h.GetReverse(account)
		if err != nil {
			return err
		}
		return r.NewMux(ctx, dispatcher.WrapLink(ctx, h.policyManager, h.stats, link), h.observer, dispatch)
	}

	if err := dispatch.DispatchLink(ctx, request.Destination(), link); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil
}

func accountFlowMismatchError(id *protocol.ID, flow string) *errors.Error {
	return errors.New("account ", id, " is not able to use the flow ", flow).AtWarning()
}

func accountEmptyFlowError(id *protocol.ID) *errors.Error {
	return errors.New("account ", id, " is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters.").AtWarning()
}

func unknownRequestFlowError(flow string) *errors.Error {
	return errors.New("unknown request flow ", flow).AtWarning()
}

func invalidOuterTLSVersionError(flow string, version uint16) *errors.Error {
	return errors.New(`failed to use `, flow, `, found outer tls version `, version).AtWarning()
}

func flowDoesNotSupportUDPError(flow string) *errors.Error {
	return errors.New(flow, " doesn't support UDP").AtWarning()
}

func forwardProxyNotAllowedError(id *protocol.ID) *errors.Error {
	return errors.New("for safety reasons, user ", id.String(), " is not allowed to use forward proxy")
}

type Reverse struct {
	tag    string
	picker *reverse.StaticMuxPicker
	client *mux.ClientManager
}

func (r *Reverse) Tag() string {
	return r.tag
}

func (r *Reverse) NewMux(ctx context.Context, link *transport.Link, observer features.Feature, dispatcher routing.Dispatcher) error {
	scope := session.PresenceScope{}
	if source, ok := dispatcher.(session.PresenceProviderSource); ok && source.PresenceProvider() != nil {
		scope = source.PresenceProvider().SnapshotPresence(ctx)
	}
	muxClient, err := mux.NewClientWorkerWithPresence(*link, mux.ClientStrategy{}, scope)
	if err != nil {
		return errors.New("failed to create mux client worker").Base(err).AtWarning()
	}
	worker, err := reverse.NewPortalWorker(muxClient)
	if err != nil {
		return errors.New("failed to create portal worker").Base(err).AtWarning()
	}
	r.picker.AddWorker(worker)
	if burstObs, ok := observer.(extension.BurstObservatory); ok {
		go burstObs.Check([]string{r.Tag()})
	}
	select {
	case <-ctx.Done():
	case <-muxClient.WaitClosed():
	}
	return nil
}

func (r *Reverse) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob != nil {
		if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
			link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
			link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		}
		r.client.DispatchRVS(session.ContextWithIsReverseMux(ctx, true), link)
	}
}

func (r *Reverse) Start() error {
	return nil
}

func (r *Reverse) Close() error {
	return r.picker.Close()
}

func (r *Reverse) SenderSettings() *serial.TypedMessage {
	return nil
}

func (r *Reverse) ProxySettings() *serial.TypedMessage {
	return nil
}

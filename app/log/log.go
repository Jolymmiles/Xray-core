package log

import (
	"context"
	stderrors "errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

// Instance is a log.Handler that handles logs.
type Instance struct {
	sync.RWMutex
	config           *Config
	accessLogger     log.Handler
	errorLogger      log.Handler
	structuredLogger log.Handler
	active           bool
	dns              bool
	mask4            int
	mask6            int
	state            atomic.Pointer[instanceState]
}

type instanceState struct {
	usage            sync.RWMutex
	retired          bool
	active           bool
	maskAddress      bool
	mask4            int
	mask6            int
	dns              bool
	accessLogger     log.Handler
	errorLogger      log.Handler
	structuredLogger log.Handler
	errorLevel       log.Severity
}

func (g *Instance) acquireState() *instanceState {
	for {
		state := g.state.Load()
		if state == nil {
			return nil
		}
		state.usage.RLock()
		if !state.retired {
			return state
		}
		state.usage.RUnlock()
	}
}

func closeState(state *instanceState) error {
	if state == nil {
		return nil
	}
	state.usage.Lock()
	state.retired = true
	state.usage.Unlock()
	return stderrors.Join(
		common.Close(state.accessLogger),
		common.Close(state.errorLogger),
		common.Close(state.structuredLogger),
	)
}

func (g *Instance) publishState() {
	g.state.Store(&instanceState{
		active:           g.active,
		maskAddress:      g.config != nil && g.config.MaskAddress != "",
		mask4:            g.mask4,
		mask6:            g.mask6,
		dns:              g.dns,
		accessLogger:     g.accessLogger,
		errorLogger:      g.errorLogger,
		structuredLogger: g.structuredLogger,
		errorLevel:       g.config.GetErrorLogLevel(),
	})
}

// New creates a new log.Instance based on the given config.
func New(ctx context.Context, config *Config) (*Instance, error) {
	m4, m6, err := ParseMaskAddress(config.MaskAddress)
	if err != nil {
		return nil, err
	}

	g := &Instance{
		config: config,
		active: false,
		dns:    config.EnableDnsLog,
		mask4:  m4,
		mask6:  m6,
	}
	log.RegisterHandler(g)

	// start logger now,
	// then other modules will be able to log during initialization
	if err := g.startInternal(); err != nil {
		return nil, err
	}

	errors.LogDebug(ctx, "Logger started")
	return g, nil
}

func (g *Instance) buildHandlers() (access, errorLog, structured log.Handler, err error) {
	if len(g.config.Outputs) > 0 {
		structured, err = createStructuredHandler(g.config.Outputs, g.config.MaskAddress != "", g.mask4, g.mask6)
		return
	}
	access, err = createHandler(g.config.AccessLogType, HandlerCreatorOptions{Path: g.config.AccessLogPath})
	if err != nil {
		return nil, nil, nil, errors.New("failed to initialize access logger").Base(err).AtWarning()
	}
	errorLog, err = createHandler(g.config.ErrorLogType, HandlerCreatorOptions{Path: g.config.ErrorLogPath})
	if err != nil {
		common.Close(access)
		return nil, nil, nil, errors.New("failed to initialize error logger").Base(err).AtWarning()
	}
	return
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return (*Instance)(nil)
}

func (g *Instance) startInternal() error {
	g.Lock()
	defer g.Unlock()

	if g.active {
		return nil
	}

	accessLogger, errorLogger, structuredLogger, err := g.buildHandlers()
	if err != nil {
		return errors.New("failed to initialize logger").Base(err).AtWarning()
	}
	g.accessLogger = accessLogger
	g.errorLogger = errorLogger
	g.structuredLogger = structuredLogger
	g.active = true
	g.publishState()

	return nil
}

// Restart builds and publishes a complete replacement before draining the old
// handlers. A replacement failure leaves the current runtime active.
func (g *Instance) Restart() error {
	g.Lock()
	if !g.active {
		g.Unlock()
		return g.startInternal()
	}
	accessLogger, errorLogger, structuredLogger, err := g.buildHandlers()
	if err != nil {
		g.Unlock()
		return err
	}
	oldState := g.state.Load()
	g.accessLogger = accessLogger
	g.errorLogger = errorLogger
	g.structuredLogger = structuredLogger
	g.publishState()
	g.Unlock()

	return closeState(oldState)
}

// Start implements common.Runnable.Start().
func (g *Instance) Start() error {
	return g.startInternal()
}

// Handle implements log.Handler.
func (g *Instance) Handle(msg log.Message) {
	state := g.acquireState()
	if state != nil {
		defer state.usage.RUnlock()
	}
	if state == nil || !state.active {
		return
	}
	if state.structuredLogger != nil {
		state.structuredLogger.Handle(msg)
		return
	}

	var Msg log.Message
	if state.maskAddress {
		Msg = &MaskedMsgWrapper{
			Message: msg,
			Mask4:   state.mask4,
			Mask6:   state.mask6,
		}
	} else {
		Msg = msg
	}

	switch msg := msg.(type) {
	case *log.AccessMessage:
		if state.accessLogger != nil {
			state.accessLogger.Handle(Msg)
		}
	case *log.DNSLog:
		if state.dns && state.accessLogger != nil {
			state.accessLogger.Handle(Msg)
		}
	case *log.GeneralMessage:
		if state.errorLogger != nil && msg.Severity <= state.errorLevel {
			state.errorLogger.Handle(Msg)
		}
	default:
		// Swallow
	}
}

// Enabled implements log.SeverityFilter.
func (g *Instance) Enabled(severity log.Severity) bool {
	state := g.acquireState()
	if state != nil {
		defer state.usage.RUnlock()
	}
	if state != nil && state.active && state.structuredLogger != nil {
		if filter, ok := state.structuredLogger.(log.SeverityFilter); ok {
			return filter.Enabled(severity)
		}
		return true
	}
	return state != nil && state.active && state.errorLogger != nil && severity <= state.errorLevel
}

// StructuredStats returns a point-in-time operational snapshot for every
// configured structured output. Legacy logger configurations return nil.
func (g *Instance) StructuredStats() []log.OutputStats {
	state := g.acquireState()
	if state != nil {
		defer state.usage.RUnlock()
	}
	if state == nil || state.structuredLogger == nil {
		return nil
	}
	provider, ok := state.structuredLogger.(interface{ Runtime() *log.Runtime })
	if !ok {
		return nil
	}
	return provider.Runtime().Stats()
}

// Close implements common.Closable.Close().
func (g *Instance) Close() error {
	errors.LogDebug(context.Background(), "Logger closing")

	g.Lock()

	if !g.active {
		g.Unlock()
		return nil
	}

	oldState := g.state.Load()
	g.active = false
	g.accessLogger = nil
	g.errorLogger = nil
	g.structuredLogger = nil
	g.publishState()
	g.Unlock()

	return closeState(oldState)
}

func ParseMaskAddress(c string) (int, int, error) {
	var m4, m6 int
	switch c {
	case "half":
		m4, m6 = 16, 32
	case "quarter":
		m4, m6 = 8, 16
	case "full":
		m4, m6 = 0, 0
	case "":
		// do nothing
	default:
		if parts := strings.Split(c, "+"); len(parts) > 0 {
			if len(parts) >= 1 && parts[0] != "" {
				i, err := strconv.Atoi(strings.TrimPrefix(parts[0], "/"))
				if err != nil {
					return 32, 128, err
				}
				m4 = i
			}
			if len(parts) >= 2 && parts[1] != "" {
				i, err := strconv.Atoi(strings.TrimPrefix(parts[1], "/"))
				if err != nil {
					return 32, 128, err
				}
				m6 = i
			}
		}
	}

	if m4%8 != 0 || m4 > 32 || m4 < 0 {
		return 32, 128, errors.New("Log Mask: ipv4 mask must be divisible by 8 and between 0-32")
	}

	return m4, m6, nil
}

// MaskedMsgWrapper is to wrap the string() method to mask IP addresses in the log.
type MaskedMsgWrapper struct {
	log.Message
	Mask4 int
	Mask6 int
}

var (
	ipv4Regex = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	ipv6Regex = regexp.MustCompile(`(?:[\da-fA-F]{0,4}:[\da-fA-F]{0,4}){2,7}`)
)

func (m *MaskedMsgWrapper) String() string {
	str := m.Message.String()

	// Process ipv4
	maskedMsg := ipv4Regex.ReplaceAllStringFunc(str, func(s string) string {
		if m.Mask4 == 32 {
			return s
		}
		if m.Mask4 == 0 {
			return "[Masked IPv4]"
		}

		parts := strings.Split(s, ".")
		for i := m.Mask4 / 8; i < 4; i++ {
			parts[i] = "*"
		}
		return strings.Join(parts, ".")
	})

	// process ipv6
	maskedMsg = ipv6Regex.ReplaceAllStringFunc(maskedMsg, func(s string) string {
		if m.Mask6 == 128 {
			return s
		}
		if m.Mask6 == 0 {
			return "Masked IPv6"
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return s
		}
		return ip.Mask(net.CIDRMask(m.Mask6, 128)).String() + "/" + strconv.Itoa(m.Mask6)
	})

	return maskedMsg
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

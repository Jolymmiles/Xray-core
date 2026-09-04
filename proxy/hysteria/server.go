package hysteria

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
	sessionPolicy policy.Session
}

var anonymousHysteriaUser = new(protocol.MemoryUser)

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*hysteria.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}

	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get hysteria user").Base(err).AtError()
		}

		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}
	validator.Warmup()

	return &Server{
		config:        config,
		validator:     validator,
		policyManager: p,
		sessionPolicy: p.ForLevel(0),
	}, nil
}

func (s *Server) HysteriaInboundValidator() *account.Validator {
	return s.validator
}

func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return s.validator.Add(user)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	return s.validator.DelByEmail(email)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "hysteria"
	inbound.CanSpliceCopy = 3
	inbound.User = anonymousHysteriaUser

	iConn := stat.TryUnwrapStatsConn(conn)

	if v, ok := iConn.(interface{ User() *protocol.MemoryUser }); ok {
		user := v.User()
		if user != nil {
			inbound.User = user
			inbound.VlessRoute = user.Account.(*account.MemoryAccount).VR
		}
	}

	if _, ok := iConn.(*hysteria.InterConn); ok {
		reader := newPooledUDPReader(conn)
		defer releasePooledUDPReader(reader)

		b, packetDestination, err := reader.readBufferPacket()
		if err != nil {
			return err
		}
		destination := reader.serverPacketDestination(packetDestination)

		reader.firstBuf = b

		writer := &reader.serverWriter
		writer.writer = conn
		writer.addr = reader.serverPacketAddress(packetDestination)
		reader.link.Reader = reader
		reader.link.Writer = writer
		return dispatcher.DispatchLink(ctx, destination, &reader.link)
	} else {
		sessionPolicy := s.policyForLevel(inbound.User.Level)

		common.Must(conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)))
		request, err := readServerTCPRequest(conn)
		if err != nil {
			log.Record(&log.AccessMessage{
				From:   conn.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			return errors.New("failed to create request from: ", conn.RemoteAddr()).Base(err)
		}
		defer releaseServerTCPRequest(request)
		common.Must(conn.SetReadDeadline(time.Time{}))

		dest := request.destination
		// Dispatchers and asynchronous logs may retain the destination after
		// this request's parsing storage returns to its pool.
		if dest.Address.Family().IsDomain() {
			dest.Address = net.DomainAddress(strings.Clone(dest.Address.Domain()))
		} else {
			dest.Address = net.IPAddress(dest.Address.IP())
		}
		from, to := net.FormatAccessEndpointsFromAddr(conn.RemoteAddr(), dest)
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			FromString: from,
			ToString:   to,
			Status:     log.AccessAccepted,
			Email:      inbound.User.Email,
		})
		if log.ShouldLog(log.Severity_Info) {
			errors.LogInfo(ctx, "tunnelling request to ", dest)
		}

		wireWriter := buf.NewPooledWriter(conn)
		defer buf.ReleasePooledWriter(wireWriter)
		responseWriter, ok := wireWriter.(io.Writer)
		if !ok {
			return errors.New("failed to create byte response writer")
		}
		err = writeTCPResponseOK(responseWriter)
		if err != nil {
			return errors.New("failed to write response").Base(err)
		}

		reader := buf.NewPooledReader(conn)
		defer buf.ReleasePooledReader(reader)
		request.link.Reader = reader
		request.link.Writer = wireWriter
		return dispatcher.DispatchLink(ctx, dest, &request.link)
	}
}

func (s *Server) policyForLevel(level uint32) policy.Session {
	if level == 0 {
		return s.sessionPolicy
	}
	return s.policyManager.ForLevel(level)
}

func parseServerTCPDestination(address string) (net.Destination, error) {
	if len(address) > 0 && address[0] != '[' {
		colon := strings.LastIndexByte(address, ':')
		if colon >= 0 && strings.IndexByte(address[:colon], ':') < 0 {
			if port, ok := parseServerPort(address[colon+1:]); ok {
				parsedAddress := net.AnyIP
				if colon > 0 {
					host := address[:colon]
					if first := host[0]; first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' {
						parsedAddress = net.DomainAddress(host)
					} else {
						parsedAddress = net.ParseAddress(host)
					}
				}
				return net.TCPDestination(parsedAddress, port), nil
			}
		}
	}
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return net.Destination{}, err
	}
	parsedAddress := net.AnyIP
	if host != "" {
		parsedAddress = net.ParseAddress(host)
	}
	var port net.Port
	if portString != "" {
		port, err = net.PortFromString(portString)
		if err != nil {
			return net.Destination{}, err
		}
	}
	return net.TCPDestination(parsedAddress, port), nil
}

func parseServerPort(port string) (net.Port, bool) {
	if len(port) == 0 {
		return 0, true
	}
	if len(port) == 1 {
		digit := port[0] - '0'
		if digit <= 9 {
			return net.Port(digit), true
		}
		return 0, false
	}
	if len(port) == 2 {
		tens, ones := port[0]-'0', port[1]-'0'
		if tens <= 9 && ones <= 9 {
			return net.Port(tens)*10 + net.Port(ones), true
		}
		return 0, false
	}
	if len(port) == 3 {
		hundreds, tens, ones := port[0]-'0', port[1]-'0', port[2]-'0'
		if hundreds <= 9 && tens <= 9 && ones <= 9 {
			return net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
		}
		return 0, false
	}
	if len(port) == 4 {
		thousands, hundreds := port[0]-'0', port[1]-'0'
		tens, ones := port[2]-'0', port[3]-'0'
		if thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 {
			return net.Port(thousands)*1000 + net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
		}
		return 0, false
	}
	if len(port) == 5 {
		tenThousands, thousands := port[0]-'0', port[1]-'0'
		hundreds, tens, ones := port[2]-'0', port[3]-'0', port[4]-'0'
		if tenThousands <= 9 && thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 {
			value := uint32(tenThousands)*10000 + uint32(thousands)*1000 + uint32(hundreds)*100 + uint32(tens)*10 + uint32(ones)
			if value <= 65535 {
				return net.Port(value), true
			}
		}
		return 0, false
	}
	value := 0
	for index := range len(port) {
		digit := port[index]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value = value*10 + int(digit-'0')
		if value > 65535 {
			return 0, false
		}
	}
	return net.Port(value), true
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

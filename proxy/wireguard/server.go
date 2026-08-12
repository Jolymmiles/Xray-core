package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Server struct {
	conf          *DeviceConfig
	ctx           context.Context
	policyManager policy.Manager
	dispatcher    routing.Dispatcher

	tag             string
	src             net.Destination
	sniffingRequest session.SniffingRequest
	streamSettings  *internet.MemoryStreamConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	tun    tun.Device
	stack  *stack.Stack
	dev    *device.Device
	mu     sync.Mutex
	closed bool

	pub              [32]byte
	users            *sync.Map
	presence         *wireGuardPresence
	presenceProvider session.PresenceProvider
	observation      atomic.Uint64
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)
	d := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	inbound := session.InboundFromContext(ctx)
	content := session.ContentFromContext(ctx)
	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	tag := inbound.Tag
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter
	if len(tag) > 0 && p.ForSystem().Stats.InboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && p.ForSystem().Stats.InboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			downlinkCounter = c
		}
	}

	localAddresses := make([]netip.Addr, 0, len(conf.Endpoint))
	for _, localaddress := range conf.Endpoint {
		addr, err := netip.ParseAddr(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, addr)
			continue
		}
		prefix, err := netip.ParsePrefix(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, prefix.Addr())
			continue
		}
		return nil, err
	}

	tun, _, stack, err := CreateNetTUN(localAddresses, nil, int(conf.Mtu), false)
	if err != nil {
		return nil, err
	}

	pri := common.Must2(ParseKey(conf.SecretKey))
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, pri)

	users := &sync.Map{}
	for _, u := range conf.Users {
		user, err := u.ToMemoryUser()
		if err != nil {
			return nil, err
		}
		users.Store(user.Account.(*MemoryAccount).Pub, user)
	}

	var presenceProvider session.PresenceProvider
	if source, ok := d.(session.PresenceProviderSource); ok {
		presenceProvider = source.PresenceProvider()
	}
	return &Server{
		conf:          conf,
		ctx:           core.ToBackgroundDetachedContext(ctx),
		policyManager: p,
		dispatcher:    d,

		tag:             inbound.Tag,
		src:             inbound.Source,
		sniffingRequest: content.SniffingRequest,
		streamSettings:  streamSettings,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,

		tun:   tun,
		stack: stack,

		pub:              pub,
		users:            users,
		presence:         newWireGuardPresence(),
		presenceProvider: presenceProvider,
	}, nil
}

func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev == nil {
		return errors.New("too early")
	}
	peer := user.Account.(*MemoryAccount)
	if peer.Pub == s.pub {
		return errors.New("invalid public key")
	}
	var sb strings.Builder
	sb.WriteString("public_key=" + hex.EncodeToString(peer.Pub[:]) + "\n")
	sb.WriteString("replace_allowed_ips=true\n")
	for i := range peer.AllowedIPs {
		sb.WriteString("allowed_ip=" + peer.AllowedIPs[i].String() + "\n")
	}
	if peer.PreSharedKey != "" {
		sb.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
	}
	if peer.KeepAlive != "" {
		sb.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
	}
	err := s.dev.IpcSet(sb.String())
	if err != nil {
		return err
	}
	s.users.Store(peer.Pub, user)
	s.presence.Allow(peer.Pub)
	return nil
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev == nil {
		return errors.New("too early")
	}
	if user := s.GetUser(ctx, email); user != nil {
		peer := user.Account.(*MemoryAccount)
		err := s.dev.IpcSet("public_key=" + hex.EncodeToString(peer.Pub[:]) + "\nremove=true\n")
		if err != nil {
			return err
		}
		s.presence.Remove(peer.Pub)
		s.users.Delete(peer.Pub)
	}
	return nil
}

func (s *Server) GetUser(ctx context.Context, email string) (user *protocol.MemoryUser) {
	s.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (s *Server) GetUserByAddr(ctx context.Context, addr netip.Addr) (user *protocol.MemoryUser) {
	s.users.Range(func(key, value any) bool {
		peer := value.(*protocol.MemoryUser).Account.(*MemoryAccount)
		for i := range peer.AllowedIPs {
			if peer.AllowedIPs[i].Contains(addr) {
				user = value.(*protocol.MemoryUser)
				return false
			}
		}
		return true
	})
	return
}

func (s *Server) GetUsers(ctx context.Context) (users []*protocol.MemoryUser) {
	s.users.Range(func(key, value interface{}) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (s *Server) GetUsersCount(context.Context) (count int64) {
	s.users.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return
}

// Network implements proxy.Inbound.Network.
func (*Server) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound.Process.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

// Close implements common.Closable.Close.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	dev, tunnel := s.dev, s.tun
	s.dev, s.tun = nil, nil
	s.mu.Unlock()
	if dev != nil {
		dev.Close()
	} else if tunnel != nil {
		_ = tunnel.Close()
	}
	s.presence.Close()
	return nil
}

// Start implements common.Runnable.Start.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("wireguard server closed")
	}
	if s.dev != nil {
		return nil
	}
	if s.src.Address.Family().IsDomain() {
		return errors.New("address is domain")
	}
	listenFunc := func() (net.PacketConn, error) {
		pktConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: s.src.Address.IP(), Port: int(s.src.Port)}, s.streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}
		if s.streamSettings.UdpmaskManager != nil {
			newConn, err := s.streamSettings.UdpmaskManager.WrapPacketConnServer(pktConn)
			if err != nil {
				pktConn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			pktConn = newConn
		}
		if s.uplinkCounter != nil || s.downlinkCounter != nil {
			pktConn = &PacketCounterConnection{
				PacketConn:   pktConn,
				ReadCounter:  s.uplinkCounter,
				WriteCounter: s.downlinkCounter,
			}
		}
		return pktConn, nil
	}
	bind := &bind{
		listenFunc: listenFunc,
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  fmt.Sprintf(format, args...),
			})
		},
		Errorf: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf(format, args...),
			})
		},
	}
	observedTun := &authenticatedTun{Device: s.tun}
	dev := device.NewDevice(observedTun, bind, logger)
	observedTun.observe = func(bufs [][]byte, offset int) {
		s.observeAuthenticatedData(dev, bufs, offset)
	}
	var cfg strings.Builder
	cfg.WriteString("private_key=" + s.conf.SecretKey + "\n")
	s.users.Range(func(key, value any) bool {
		peer := value.(*protocol.MemoryUser).Account.(*MemoryAccount)
		cfg.WriteString("public_key=" + hex.EncodeToString(peer.Pub[:]) + "\n")
		for i := range peer.AllowedIPs {
			cfg.WriteString("allowed_ip=" + peer.AllowedIPs[i].String() + "\n")
		}
		if peer.PreSharedKey != "" {
			cfg.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
		}
		if peer.KeepAlive != "" {
			cfg.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
		}
		return true
	})
	err := dev.IpcSet(cfg.String())
	if err != nil {
		return err
	}
	err = dev.Up()
	if err != nil {
		return err
	}
	s.dev = dev
	createForwarder(s.stack, s.HandleConnection)
	return nil
}

func (s *Server) HandleConnection(conn net.Conn, dest net.Destination) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())

	remote := conn.RemoteAddr()
	if remote == nil {
		errors.LogError(context.Background(), "nil remote")
		return
	}

	var addr netip.Addr
	switch v := remote.(type) {
	case *net.TCPAddr:
		addr, _ = netip.AddrFromSlice(v.IP)
	case *net.UDPAddr:
		addr, _ = netip.AddrFromSlice(v.IP)
	default:
		errors.LogError(context.Background(), "invalid addr type ", reflect.TypeOf(v))
		return
	}

	pub, endpoint, user, ok := s.authenticatedPeer(addr)
	if !ok {
		errors.LogError(context.Background(), "nil user form ", remote, " to ", dest)
		return
	}
	flow := s.presence.Open(pub)
	if flow == nil {
		errors.LogError(context.Background(), "missing authenticated endpoint binding")
		return
	}
	defer flow.Close()

	source := net.DestinationFromAddr(remote)
	inbound := session.Inbound{
		Name:          "wireguard",
		Tag:           s.tag,
		CanSpliceCopy: 3,
		Source:        source,
		PhysicalPeer:  endpoint.Addr().Unmap(),
		User:          user,
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithPresenceMode(ctx, session.PresenceModeExternal)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: s.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", dest)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := s.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

func (s *Server) observeAuthenticatedData(dev *device.Device, bufs [][]byte, offset int) {
	state, err := dev.IpcGet()
	if err != nil {
		return
	}
	seen := make(map[netip.Addr]struct{}, len(bufs))
	for _, buffer := range bufs {
		if offset < 0 || offset > len(buffer) {
			continue
		}
		inner, ok := wireGuardPacketSource(buffer[offset:])
		if !ok {
			continue
		}
		if _, duplicate := seen[inner]; duplicate {
			continue
		}
		seen[inner] = struct{}{}
		pub, endpoint, ok := authenticatedPeerState(state, inner)
		if !ok {
			continue
		}
		value, ok := s.users.Load(pub)
		if !ok {
			continue
		}
		user := value.(*protocol.MemoryUser)
		inbound := &session.Inbound{
			Name:         "wireguard",
			Tag:          s.tag,
			PhysicalPeer: endpoint.Addr().Unmap(),
			User:         user,
		}
		ctx := session.ContextWithInbound(s.ctx, inbound)
		scope := session.PresenceScope{}
		if s.presenceProvider != nil {
			scope = s.presenceProvider.SnapshotPresence(ctx)
		}
		s.presence.Observe(pub, s.observation.Add(1), endpoint.Addr(), scope)
	}
}

func (s *Server) authenticatedPeer(inner netip.Addr) ([32]byte, netip.AddrPort, *protocol.MemoryUser, bool) {
	s.mu.Lock()
	dev := s.dev
	s.mu.Unlock()
	if dev == nil {
		return [32]byte{}, netip.AddrPort{}, nil, false
	}
	state, err := dev.IpcGet()
	if err != nil {
		return [32]byte{}, netip.AddrPort{}, nil, false
	}
	pub, endpoint, ok := authenticatedPeerState(state, inner)
	if !ok {
		return [32]byte{}, netip.AddrPort{}, nil, false
	}
	value, ok := s.users.Load(pub)
	if !ok {
		return [32]byte{}, netip.AddrPort{}, nil, false
	}
	return pub, endpoint, value.(*protocol.MemoryUser), true
}

func wireGuardPacketSource(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), true
	default:
		return netip.Addr{}, false
	}
}

func ParseKey(str string) (*[32]byte, error) {
	slice, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	if len(slice) != 32 {
		return nil, errors.New("len(slice) != 32")
	}
	return (*[32]byte)(slice), nil
}

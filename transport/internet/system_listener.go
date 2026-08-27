package internet

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

var effectiveListener = DefaultListener{}

type DefaultListener struct {
	controllers []func(network, address string, c syscall.RawConn) error
}

type physicalPeerListener struct {
	net.Listener
	proxyProtocol bool
}

type acceptedProxyProtocolConn struct {
	*proxyproto.Conn
	acceptedPeer netip.Addr
}

func newAcceptedProxyProtocolConn(conn net.Conn) *acceptedProxyProtocolConn {
	accepted := new(acceptedProxyProtocolConn)
	accepted.Conn = proxyproto.NewConn(
		conn,
		proxyproto.WithPolicy(proxyproto.REQUIRE),
		proxyproto.ValidateHeader(func(header *proxyproto.Header) error {
			if header == nil || !header.Command.IsProxy() || !header.TransportProtocol.IsStream() {
				return nil
			}
			peer, ok := net.CanonicalPhysicalPeer(header.SourceAddr)
			if ok {
				accepted.acceptedPeer = peer
			}
			return nil
		}),
	)
	return accepted
}

func (c *acceptedProxyProtocolConn) AcceptedProxyPeer() netip.Addr {
	if c == nil || c.Conn == nil {
		return netip.Addr{}
	}
	_ = c.ProxyHeader()
	return c.acceptedPeer
}

// CloseWrite forwards half-close to the physical connection. proxyproto.Conn
// re-exports ReadFrom/WriteTo/TCPConn/UnixConn/UDPConn but neither CloseWrite
// nor SyscallConn, so without these hooks REALITY's server handshake type
// assertion (reality.CloseWriteConn) panics on any composition that reaches
// the wrapper without an outer provenance carrier. Underlying connections that
// cannot half-close degrade to a silent no-FIN rather than crashing the accept
// goroutine; REALITY ignores the returned error, matching that fail-soft trade.
func (c *acceptedProxyProtocolConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return errors.New("cannot CloseWrite a nil PROXY protocol connection")
	}
	if closer, ok := c.Conn.Raw().(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.New("underlying connection does not support CloseWrite")
}

// SyscallConn keeps tproxy and redirect consumers working behind the wrapper.
func (c *acceptedProxyProtocolConn) SyscallConn() (syscall.RawConn, error) {
	if c == nil || c.Conn == nil {
		return nil, errors.New("cannot access RawConn of a nil PROXY protocol connection")
	}
	if sc, ok := c.Conn.Raw().(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("underlying connection does not expose a RawConn")
}

func (l *physicalPeerListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn = net.CapturePhysicalPeer(conn)
	if !l.proxyProtocol {
		return conn, nil
	}
	return net.PreservePhysicalPeer(conn, newAcceptedProxyProtocolConn(conn)), nil
}

// CapturePhysicalPeerListener freezes accepted peers before transport wrappers.
func CapturePhysicalPeerListener(listener net.Listener) net.Listener {
	return &physicalPeerListener{Listener: listener}
}

func getControlFunc(ctx context.Context, sockopt *SocketConfig, controllers []func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			for _, controller := range controllers {
				if err := controller(network, address, c); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply external controller")
				}
			}

			if sockopt != nil {
				if err := applyInboundSocketOptions(network, fd, sockopt); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply socket options to incoming connection")
				}
			}

			setReusePort(fd)
		})
	}
}

// For some reason, other component of ray will assume the listener is a TCP listener and have valid remote address.
// But in fact it doesn't. So we need to wrap the listener to make it return 0.0.0.0(unspecified) as remote address.
// If other issues encountered, we should able to fix it here.
type UnixListenerWrapper struct {
	*net.UnixListener
	locker *FileLocker
}

func (l *UnixListenerWrapper) Accept() (net.Conn, error) {
	conn, err := l.UnixListener.Accept()
	if err != nil {
		return nil, err
	}
	return &UnixConnWrapper{UnixConn: conn.(*net.UnixConn)}, nil
}

func (l *UnixListenerWrapper) Close() error {
	if l.locker != nil {
		l.locker.Release()
		l.locker = nil
	}
	return l.UnixListener.Close()
}

type UnixConnWrapper struct {
	*net.UnixConn
}

func (conn *UnixConnWrapper) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP: []byte{0, 0, 0, 0},
	}
}

func (dl *DefaultListener) Listen(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (l net.Listener, err error) {
	var lc net.ListenConfig
	var network, address string
	// callback is called after the Listen function returns
	callback := func(l net.Listener, err error) (net.Listener, error) {
		return l, err
	}

	switch addr := addr.(type) {
	case *net.TCPAddr:
		network = addr.Network()
		address = addr.String()
		lc.Control = getControlFunc(ctx, sockopt, dl.controllers)
		// default disable keepalive
		lc.KeepAlive = -1
		if sockopt != nil {
			if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
				return nil, errors.New("invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ", sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval)
			}
			lc.KeepAliveConfig = net.KeepAliveConfig{
				Enable:   false,
				Idle:     -1,
				Interval: -1,
				Count:    -1,
			}
			if sockopt.TcpKeepAliveIdle > 0 {
				lc.KeepAliveConfig.Enable = true
				lc.KeepAliveConfig.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
			}
			if sockopt.TcpKeepAliveInterval > 0 {
				lc.KeepAliveConfig.Enable = true
				lc.KeepAliveConfig.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
			}
			if sockopt.TcpMptcp {
				lc.SetMultipathTCP(true)
			}
		}
	case *net.UnixAddr:
		lc.Control = nil
		network = addr.Network()
		address = addr.Name

		if (runtime.GOOS == "linux" || runtime.GOOS == "android") && address[0] == '@' {
			// linux abstract unix domain socket is lockfree
			if len(address) > 1 && address[1] == '@' {
				// but may need padding to work with haproxy
				fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
				copy(fullAddr, address[1:])
				address = string(fullAddr)
			}
		} else {
			// split permission from address
			var filePerm *os.FileMode
			if s := strings.Split(address, ","); len(s) == 2 {
				address = s[0]
				perm, perr := strconv.ParseUint(s[1], 8, 32)
				if perr != nil {
					return nil, errors.New("failed to parse permission: " + s[1]).Base(perr)
				}

				mode := os.FileMode(perm)
				filePerm = &mode
			}
			// normal unix domain socket needs lock
			locker := &FileLocker{
				path: address + ".lock",
			}
			if err := locker.Acquire(); err != nil {
				return nil, err
			}

			// set callback to combine listener and set permission
			callback = func(l net.Listener, err error) (net.Listener, error) {
				if err != nil {
					locker.Release()
					return nil, err
				}
				l = &UnixListenerWrapper{UnixListener: l.(*net.UnixListener), locker: locker}
				if filePerm == nil {
					return l, nil
				}
				err = os.Chmod(address, *filePerm)
				if err != nil {
					l.Close()
					return nil, errors.New("failed to set permission for " + address).Base(err)
				}
				return l, nil
			}
		}
	}

	l, err = callback(lc.Listen(ctx, network, address))
	if err == nil && sockopt != nil && sockopt.AcceptProxyProtocol {
		l = &physicalPeerListener{
			Listener:      l,
			proxyProtocol: true,
		}
	}
	return l, err
}

func (dl *DefaultListener) ListenPacket(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (net.PacketConn, error) {
	var lc net.ListenConfig

	lc.Control = getControlFunc(ctx, sockopt, dl.controllers)

	return lc.ListenPacket(ctx, addr.Network(), addr.String())
}

// RegisterListenerController adds a controller to the effective system listener.
// The controller can be used to operate on file descriptors before they are put into use.
//
// xray:api:beta
func RegisterListenerController(controller func(network, address string, c syscall.RawConn) error) error {
	if controller == nil {
		return errors.New("nil listener controller")
	}

	effectiveListener.controllers = append(effectiveListener.controllers, controller)
	return nil
}

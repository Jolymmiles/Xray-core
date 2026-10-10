package hysteria

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type client struct {
	lock         chan struct{}
	instance     *core.Instance
	forced       bool
	dest         net.Destination
	config       *Config
	tlsConfig    *gotls.Config
	socketConfig *internet.SocketConfig
	finalMask    *finalmask.FinalMask
	quicParams   *internet.QuicParams

	conn    *quic.Conn
	tr      *quic.Transport
	pktConn net.PacketConn
	udpSM   *udpSessionManager
}

func (c *client) status() status {
	if c.conn == nil {
		return StatusNull
	}
	select {
	case <-c.conn.Context().Done():
		return StatusInactive
	default:
		return StatusActive
	}
}

func (c *client) close() {
	c.conn.CloseWithError(closeErrCodeOK, "")
	c.tr.Close()
	c.pktConn.Close()
	c.conn = nil
	c.tr = nil
	c.pktConn = nil
	c.udpSM = nil
}

func (c *client) dial(ctx context.Context) error {
	// A done context and a free client lock are both ready, so the lock can
	// be taken for a dial that is already canceled.
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.forced {
		return errors.New("client is closed")
	}

	switch c.status() {
	case StatusActive:
		return nil
	case StatusInactive:
		c.close()
	}

	quicParams := c.quicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		ChromeParrot:                   !quicParams.DisableChromeParrot,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	// if quicParams.KeepAlivePeriod == 0 {
	// 	quicConfig.KeepAlivePeriod = 10 * time.Second
	// }

	var pktConn net.PacketConn
	var udpAddr net.Addr
	if c.finalMask != nil {
		conn, err := c.finalMask.DialUDP(ctx, c.dest)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		pktConn = conn.(*net.PacketConnWrapper).PacketConn
		udpAddr = conn.RemoteAddr()
	} else {
		conn, err := internet.DialSystem(ctx, c.dest, c.socketConfig)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		switch c := conn.(type) {
		case *net.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = c.RemoteAddr()
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
			udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
		default:
			panic(reflect.TypeOf(c))
		}
	}

	tr, clientTLSConfig := internet.PrepareQUICClient(pktConn, quicConfig, c.tlsConfig, quicParams)

	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: clientTLSConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   URLHost,
			Path:   URLPath,
		},
		Header: http.Header{
			RequestHeaderAuth:   []string{c.config.Auth},
			CommonHeaderCCRX:    []string{strconv.FormatUint(quicParams.BrutalDown, 10)},
			CommonHeaderPadding: []string{AuthRequestPadding.String()},
		},
	}
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		// On cancellation RoundTrip returns while HTTP/3 may still run Dial
		// on its own goroutine; Close waits for it before conn is read.
		_ = rt.Close()
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = tr.Close()
		_ = pktConn.Close()
		return err
	}
	if resp.StatusCode != StatusAuthOK {
		// Close the connection first: it then ends with the protocol error
		// alone, not with code 0 from rt.Close or a stream cancellation from
		// closing the unread body.
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = resp.Body.Close()
		_ = rt.Close()
		_ = tr.Close()
		_ = pktConn.Close()
		return errors.New("auth failed code ", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// udp, _ := strconv.ParseBool(resp.Header.Get(ResponseHeaderUDPEnabled))
	down, _ := strconv.ParseUint(resp.Header.Get(CommonHeaderCCRX), 10, 64)
	errors.LogDebug(context.Background(), "Hysteria QUIC ECHAccepted: ", conn.ConnectionState().TLS.ECHAccepted)

	switch quicParams.Congestion {
	case "reno":
	case "bbr":
		congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
	case "", "brutal":
		if quicParams.BrutalUp == 0 || down == 0 {
			congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
		} else {
			congestion.UseBrutal(conn, min(quicParams.BrutalUp, down), quicParams.BrutalDisableLossCompensation)
		}
	case "force-brutal":
		congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
	default:
		panic(quicParams.Congestion)
	}

	c.pktConn = pktConn
	c.tr = tr
	c.conn = conn
	c.udpSM = &udpSessionManager{
		conn: conn,
		m:    newUDPSessionMap(),
		next: 1,
	}
	go c.udpSM.run()

	return nil
}

func (c *client) unlock() {
	<-c.lock
}

func (c *client) tcp(ctx context.Context) (stat.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c.lock <- struct{}{}:
		defer c.unlock()
	}

	err := c.dial(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{
		stream: stream,
		local:  c.conn.LocalAddr(),
		remote: c.conn.RemoteAddr(),

		client: true,
	}, nil
}

func (c *client) udp(ctx context.Context) (stat.Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c.lock <- struct{}{}:
		defer c.unlock()
	}

	err := c.dial(ctx)
	if err != nil {
		return nil, err
	}

	return c.udpSM.udp()
}

func (c *client) clean(force bool) {
	c.lock <- struct{}{}
	if force {
		c.forced = true
	}
	if status := c.status(); force && status != StatusNull || status == StatusInactive {
		c.close()
	}
	c.unlock()
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

type clientManager struct {
	sync.RWMutex
	m map[dialerConf]*client

	// cleaning, when set by a test, runs for each captured client before its
	// instance check and cleanup, with no manager or client lock held.
	// Install it before starting cleaner passes and leave it unchanged until
	// all passes finish. Overlapping passes may call it concurrently,
	// including for a client no longer present in the pool.
	cleaning func(*client)
}

func (m *clientManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	for range ticker.C {
		m.cleanOnce()
	}
}

type pooledClient struct {
	key    dialerConf
	client *client
}

// cleanOnce runs one cleaner pass over a snapshot of the pool. It waits for
// instance status (Instance.Start and Close hold it while features start or
// close) and for client locks (a dial holds one during a handshake) without
// holding the pool lock, so neither wait stalls dials. A forced client is
// closed before it is removed, and removed only if the pool still holds it:
// an overlapping pass keeps a replacement that a dial added under the same
// key.
func (m *clientManager) cleanOnce() {
	m.RLock()
	clients := make([]pooledClient, 0, len(m.m))
	for k, c := range m.m {
		clients = append(clients, pooledClient{k, c})
	}
	m.RUnlock()

	for _, p := range clients {
		if m.cleaning != nil {
			m.cleaning(p.client)
		}
		force := p.client.instance != nil && !p.client.instance.IsRunning()
		p.client.clean(force)
		if force {
			m.Lock()
			if m.m[p.key] == p.client {
				delete(m.m, p.key)
			}
			m.Unlock()
		}
	}
}

var (
	manager     *clientManager
	initmanager sync.Once
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	initmanager.Do(func() {
		manager = &clientManager{
			m: make(map[dialerConf]*client),
		}
		go manager.clean()
	})

	return manager.dial(ctx, dest, streamSettings, tlsConfig)
}

func (m *clientManager) dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, tlsConfig *tls.Config) (stat.Connection, error) {
	datagram := DatagramFromContext(ctx)
	dest.Network = net.Network_UDP

	dialerConfKey := dialerConf{dest, streamSettings}

	m.RLock()
	c := m.m[dialerConfKey]
	m.RUnlock()

	if c == nil {
		m.Lock()
		c = m.m[dialerConfKey]
		if c == nil {
			c = &client{
				lock:         make(chan struct{}, 1),
				instance:     core.FromContext(ctx),
				dest:         dest,
				config:       streamSettings.ProtocolSettings.(*Config),
				tlsConfig:    tlsConfig.GetTLSConfig(tls.WithDestination(dest)),
				socketConfig: streamSettings.SocketSettings,
				finalMask:    streamSettings.FinalMask,
				quicParams:   streamSettings.QuicParams,
			}
			m.m[dialerConfKey] = c
		}
		m.Unlock()
	}

	if datagram {
		return c.udp(ctx)
	}
	return c.tcp(ctx)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

package websocket

import (
	"context"
	_ "embed"
	"encoding/base64"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Dial dials a WebSocket connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)
	var conn net.Conn
	if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
		ctx, cancel := context.WithCancel(ctx)
		conn = &delayDialConn{
			dialed:         make(chan struct{}),
			cancel:         cancel,
			ctx:            ctx,
			dest:           dest,
			streamSettings: streamSettings,
		}
	} else {
		var err error
		if conn, err = dialWebSocket(ctx, dest, streamSettings, nil); err != nil {
			return nil, errors.New("failed to dial WebSocket").Base(err)
		}
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			var conn net.Conn
			var err error
			if streamSettings.FinalMask != nil {
				conn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
			} else {
				conn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
			}
			if err != nil {
				return nil, errors.New("failed to dial to dest").Base(err)
			}
			return conn, err
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	tConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tConfig != nil {
		protocol = "wss"
		tlsConfig := tConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
		dialer.TLSClientConfig = tlsConfig
		if fingerprint := tls.GetFingerprint(tConfig.Fingerprint); fingerprint != nil {
			dialer.NetDialTLSContext = func(_ context.Context, _, addr string) (net.Conn, error) {
				// Like the NetDial in the dialer
				var pconn net.Conn
				var err error
				if streamSettings.FinalMask != nil {
					pconn, err = streamSettings.FinalMask.DialTCP(ctx, dest)
				} else {
					pconn, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				}
				if err != nil {
					return nil, errors.New("failed to dial to dest").Base(err)
				}

				// TLS and apply the handshake
				cn := tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				if err := cn.WebsocketHandshakeContext(ctx); err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
						return nil, err
					}
				}
				return cn, nil
			}
		}
	}

	if browser_dialer.HasBrowserDialer() {
		// For Browser Dialer's optimized IP and non-standard port
		host := wsSettings.Host
		if host == "" && tConfig.ServerName != "" {
			host = tConfig.ServerName
		}
		if host == "" {
			host = dest.Address.String()
		}
		if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
			host += ":" + dest.Port.String()
		}
		uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

		conn, err := browser_dialer.DialWS(uri, ed)
		if err != nil {
			return nil, err
		}

		return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
	}

	host := dest.Address.String()
	if !(protocol == "ws" && dest.Port == 80) && !(protocol == "wss" && dest.Port == 443) {
		host += ":" + dest.Port.String()
	}
	uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

	header := wsSettings.GetRequestHeader()
	// See dialer.DialContext()
	header.Set("Host", wsSettings.Host)
	if header.Get("Host") == "" && tConfig != nil {
		header.Set("Host", tConfig.ServerName)
	}
	if header.Get("Host") == "" {
		header.Set("Host", dest.Address.String())
	}
	if ed != nil {
		// RawURLEncoding is support by both V2Ray/V2Fly and XRay.
		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.DialContext(ctx, uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.New("failed to dial to (", uri, "): ", reason).Base(err)
	}

	return NewConnection(conn, conn.RemoteAddr(), nil, wsSettings.HeartbeatPeriod), nil
}

// delayDialConn dials on its first Write, so that the first payload can ride
// in the handshake as early data. Like any net.Conn it may be read, written
// and closed from different goroutines: a proxy reads and writes it from two
// and closes it from whichever finishes first.
type delayDialConn struct {
	cancel         context.CancelFunc
	ctx            context.Context
	dest           net.Destination
	streamSettings *internet.MemoryStreamConfig

	dialMu sync.Mutex    // held by the Write that dials
	dialed chan struct{} // closed once the dialed connection is published

	mu     sync.Mutex // orders publishing the connection against Close
	conn   atomic.Pointer[dialedConn]
	closed atomic.Bool
}

type dialedConn struct {
	net.Conn
}

var errDeadlineBeforeDial = errors.New("WebSocket early data: deadline set before the first write dialed")

// LocalAddr returns nil until the deferred WebSocket dial has completed.
func (d *delayDialConn) LocalAddr() net.Addr {
	if conn := d.conn.Load(); conn != nil {
		return conn.LocalAddr()
	}
	return nil
}

// RemoteAddr returns nil until the deferred WebSocket dial has completed.
func (d *delayDialConn) RemoteAddr() net.Addr {
	if conn := d.conn.Load(); conn != nil {
		return conn.RemoteAddr()
	}
	return nil
}

func (d *delayDialConn) Write(b []byte) (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if conn := d.conn.Load(); conn != nil {
		return conn.Write(b)
	}
	d.dialMu.Lock()
	defer d.dialMu.Unlock()
	if conn := d.conn.Load(); conn != nil {
		return conn.Write(b)
	}
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	ed := b
	if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
		ed = nil
	}
	conn, err := dialWebSocket(d.ctx, d.dest, d.streamSettings, ed)
	if err != nil {
		d.Close()
		return 0, errors.New("failed to dial WebSocket").Base(err)
	}
	// A Close during the dial found nothing to close: this Write owns the
	// connection then.
	d.mu.Lock()
	if d.closed.Load() {
		d.mu.Unlock()
		conn.Close()
		return 0, io.ErrClosedPipe
	}
	d.conn.Store(&dialedConn{conn})
	d.mu.Unlock()
	close(d.dialed)
	if ed != nil {
		return len(ed), nil
	}
	return conn.Write(b)
}

func (d *delayDialConn) Read(b []byte) (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	conn := d.conn.Load()
	if conn == nil {
		select {
		case <-d.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-d.dialed:
		}
		conn = d.conn.Load()
	}
	return conn.Read(b)
}

func (d *delayDialConn) Close() error {
	d.mu.Lock()
	if d.closed.Load() {
		d.mu.Unlock()
		return nil
	}
	d.closed.Store(true)
	conn := d.conn.Load()
	d.mu.Unlock()
	d.cancel()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (d *delayDialConn) SetDeadline(t time.Time) error {
	if conn := d.conn.Load(); conn != nil {
		return conn.SetDeadline(t)
	}
	return errDeadlineBeforeDial
}

func (d *delayDialConn) SetReadDeadline(t time.Time) error {
	if conn := d.conn.Load(); conn != nil {
		return conn.SetReadDeadline(t)
	}
	return errDeadlineBeforeDial
}

func (d *delayDialConn) SetWriteDeadline(t time.Time) error {
	if conn := d.conn.Load(); conn != nil {
		return conn.SetWriteDeadline(t)
	}
	return errDeadlineBeforeDial
}

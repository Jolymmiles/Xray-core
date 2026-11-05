package splithttp

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// swapDialerMap gives the dials of a test the XMUX managers it sets up
func swapDialerMap(t *testing.T, managers map[dialerConf]*XmuxManager) {
	t.Helper()
	globalDialerAccess.Lock()
	previous := globalDialerMap
	globalDialerMap = managers
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = previous
		globalDialerAccess.Unlock()
	})
}

// openDialer opens every stream with no network
type openDialer struct{}

func (*openDialer) IsClosed() bool { return false }

func (*openDialer) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return io.NopCloser(strings.NewReader("")), &net.TCPAddr{}, &net.TCPAddr{}, nil
}

func (*openDialer) PostPacket(_ context.Context, _, _, _ string, p buf.MultiBuffer) error {
	buf.ReleaseMulti(p)
	return nil
}

// a dial reserves the XMUX client it picks before it lets go of the dialer
// map, so with "maxConcurrency" 1 the next dial picks another client even when
// both pick before either is set up
func TestDialReservesItsXmuxClient(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}
	dest := net.TCPDestination(net.DomainAddress("xhttp.invalid"), 443)

	swapDialerMap(t, map[dialerConf]*XmuxManager{
		{dest, settings}: NewXmuxManager(&XmuxConfig{MaxConcurrency: &RangeConfig{From: 1, To: 1}}, func() XmuxConn { return &DefaultDialerClient{} }),
	})

	_, first := getHTTPClient(context.Background(), dest, settings)
	_, second := getHTTPClient(context.Background(), dest, settings)
	if first == second {
		t.Fatalf("two dials took one client with maxConcurrency 1 (running %d)", first.Running.Load())
	}
	for _, client := range []*XmuxClient{first, second} {
		if n := client.Running.Load(); n != 1 {
			t.Errorf("a client picked by one dial has %d running, want 1", n)
		}
	}
}

// a dial whose download settings lead to its upload client counts once in it
func TestDialCountsOnceInAClientItPicksTwice(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("xhttp.invalid"), 443)
	settings := &internet.MemoryStreamConfig{
		Destination:      &dest,
		ProtocolSettings: &Config{Mode: "stream-up", DownloadSettings: &internet.StreamConfig{}},
	}
	settings.DownloadSettings = settings
	manager := NewXmuxManager(&XmuxConfig{}, func() XmuxConn { return &openDialer{} })
	swapDialerMap(t, map[dialerConf]*XmuxManager{{dest, settings}: manager})

	conn, err := Dial(context.Background(), dest, settings)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	client := manager.xmuxClients[0]
	if n := client.Running.Load(); n != 1 {
		t.Errorf("an open dial has %d running in its client, want 1", n)
	}
	conn.Close()
	if n := client.Running.Load(); n != 0 {
		t.Errorf("a closed dial left %d running in its client", n)
	}
}

// a dial that fails to open its streams lets go of its clients
func TestFailedDialReleasesItsXmuxClient(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			dest := net.TCPDestination(net.DomainAddress("xhttp.invalid"), 443)
			// a host that makes no URL fails the request before any dial
			settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{Mode: mode, Host: "bad\nhost"}}
			manager := NewXmuxManager(&XmuxConfig{}, func() XmuxConn { return createHTTPClient(dest, settings) })
			swapDialerMap(t, map[dialerConf]*XmuxManager{{dest, settings}: manager})

			if conn, err := Dial(context.Background(), dest, settings); err == nil {
				conn.Close()
				t.Fatal("Dial to a host that makes no URL succeeded")
			}
			if n := manager.xmuxClients[0].Running.Load(); n != 0 {
				t.Errorf("a failed dial left %d running in its client", n)
			}
		})
	}
}

// countedBody counts its closes
type countedBody struct {
	io.Reader
	closes *atomic.Int32
}

func (b *countedBody) Close() error {
	b.closes.Add(1)
	return nil
}

// downloadDialer opens downloads and refuses uploads
type downloadDialer struct {
	openDialer
	closes atomic.Int32
}

func (d *downloadDialer) OpenStream(_ context.Context, _, _ string, body io.Reader, _ bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("upload refused")
	}
	return &countedBody{Reader: strings.NewReader(""), closes: &d.closes}, &net.TCPAddr{}, &net.TCPAddr{}, nil
}

// a stream-up dial whose upload fails after its download opened closes the
// download and lets go of both clients
func TestFailedUploadClosesTheDownload(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("xhttp.invalid"), 443)
	settings := &internet.MemoryStreamConfig{
		Destination:      &dest,
		ProtocolSettings: &Config{Mode: "stream-up", DownloadSettings: &internet.StreamConfig{}},
	}
	settings.DownloadSettings = &internet.MemoryStreamConfig{Destination: &dest, ProtocolSettings: &Config{}}
	dialer := &downloadDialer{}
	up := NewXmuxManager(&XmuxConfig{}, func() XmuxConn { return dialer })
	down := NewXmuxManager(&XmuxConfig{}, func() XmuxConn { return dialer })
	swapDialerMap(t, map[dialerConf]*XmuxManager{{dest, settings}: up, {dest, settings.DownloadSettings}: down})

	if conn, err := Dial(context.Background(), dest, settings); err == nil {
		conn.Close()
		t.Fatal("Dial with a refused upload succeeded")
	}
	if n := dialer.closes.Load(); n != 1 {
		t.Errorf("the open download was closed %d times, want 1", n)
	}
	for name, manager := range map[string]*XmuxManager{"upload": up, "download": down} {
		if n := manager.xmuxClients[0].Running.Load(); n != 0 {
			t.Errorf("a failed dial left %d running in its %s client", n, name)
		}
	}
}

package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	stdnet "net"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	proxymanoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"golang.zx2c4.com/wireguard/tun"
)

// closeCountingDevice counts the Close calls that reach the TUN and passes
// them on to the real one.
type closeCountingDevice struct {
	tun.Device
	closes atomic.Int32
}

func (d *closeCountingDevice) Close() error {
	d.closes.Add(1)
	return d.Device.Close()
}

// A WireGuard outbound creates its TUN in the constructor and its device on
// first use. Removing it through the outbound manager (HandlerService
// RemoveOutbound) must close the TUN, and closing the instance or the handler
// afterwards must not close it again.
func TestRemovedOutboundClosesTUNOnce(t *testing.T) {
	for _, test := range []struct {
		name     string
		deviceUp bool
	}{
		{name: "unused"},
		{name: "device up", deviceUp: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The peer endpoint is a socket the test owns, so nothing the
			// device sends goes to a closed port or off the host.
			peer, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })

			v, err := core.New(&core.Config{
				App: []*serial.TypedMessage{serial.ToTypedMessage(&proxyman.OutboundConfig{})},
				Outbound: []*core.OutboundHandlerConfig{{
					Tag:            "wg",
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{}}),
					ProxySettings: serial.ToTypedMessage(&DeviceConfig{
						SecretKey: newTestWireGuardKey(t),
						Endpoint:  []string{"10.0.0.2"},
						Peers: []*PeerConfig{{
							PublicKey:  newTestWireGuardKey(t),
							Endpoint:   peer.LocalAddr().String(),
							AllowedIps: []string{"0.0.0.0/0"},
						}},
						Mtu:         1420,
						IsClient:    true,
						NoKernelTun: true,
					}),
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = v.Close() })
			if err := v.Start(); err != nil {
				t.Fatal(err)
			}

			ohm := v.GetFeature(outbound.ManagerType()).(outbound.Manager)
			handler := ohm.GetHandler("wg").(*proxymanoutbound.Handler).GetOutbound().(*Handler)
			t.Cleanup(func() { _ = handler.Close() })
			device := &closeCountingDevice{}
			handler.mu.Lock()
			device.Device = handler.tun
			handler.tun = device
			handler.mu.Unlock()
			if test.deviceUp {
				if err := handler.init(context.Background()); err != nil {
					t.Fatal(err)
				}
			}

			if err := ohm.RemoveHandler(context.Background(), "wg"); err != nil {
				t.Fatal(err)
			}
			if n := device.closes.Load(); n != 1 {
				t.Fatalf("removing the outbound closed its TUN %d times, want 1", n)
			}
			if err := v.Close(); err != nil {
				t.Fatal(err)
			}
			if err := handler.Close(); err != nil {
				t.Fatal(err)
			}
			if n := device.closes.Load(); n != 1 {
				t.Fatalf("closing the instance and the handler after the removal closed the TUN %d times in total, want 1", n)
			}
		})
	}
}

func newTestWireGuardKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key.Bytes())
}

package inbound_test

import (
	stdnet "net"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// A protobuf or HandlerService config skips the JSON key checks, so a
// malformed REALITY key has to be refused when the handler is built rather
// than panic the whole process when its listener starts.
func TestAddInboundRejectsMalformedREALITYKeys(t *testing.T) {
	validKey := make([]byte, 32)
	validKey[0] = 1
	tests := []struct {
		name   string
		config *reality.Config
		want   string
	}{
		{"short private key", &reality.Config{PrivateKey: []byte{1}}, "private key"},
		{"no private key", &reality.Config{}, "private key"},
		{"short ML-DSA seed", &reality.Config{PrivateKey: validKey, Mldsa65Seed: []byte{1}}, "ML-DSA-65 seed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := core.New(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(&dispatcher.Config{}),
				serial.ToTypedMessage(&proxyman.InboundConfig{}),
				serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}

			test.config.Type = "tcp"
			test.config.Dest = "127.0.0.1:443"
			security := serial.ToTypedMessage(test.config)
			config := &core.InboundHandlerConfig{
				Tag: "malformed-reality",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(freeTCPPort(t))}},
					StreamSettings: &internet.StreamConfig{
						ProtocolName:     "tcp",
						SecurityType:     security.Type,
						SecuritySettings: []*serial.TypedMessage{security},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
					RewritePort:     7,
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			}
			err = core.AddInboundHandler(server, config)
			if err == nil {
				t.Fatal("AddInboundHandler accepted a malformed REALITY key")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AddInboundHandler error %q does not name the %s", err, test.want)
			}
		})
	}
}

func freeTCPPort(t *testing.T) net.Port {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
}

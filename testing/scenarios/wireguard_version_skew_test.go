//go:build integration

package scenarios

import (
	"encoding/hex"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
)

func TestWireGuardVersionSkew(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level WireGuard version-skew matrix")
	}
	common.Must(BuildXray())
	oldBinary := buildReverseCompatibilityBinary(t)
	for _, test := range []struct{ name, serverBinary, clientBinary string }{
		{"old-client-new-server", testBinaryPath, oldBinary},
		{"new-client-old-server", oldBinary, testBinaryPath},
		{"new-client-new-server", testBinaryPath, testBinaryPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			echo := tcp.Server{MsgProcessor: xor, Listen: net.AnyIP}
			destination, err := echo.Start()
			common.Must(err)
			t.Cleanup(func() { _ = echo.Close() })
			hostIP := wireGuardHostIP(t)
			destination.Address = net.IPAddress(hostIP.AsSlice())

			serverPort, clientPort := udp.PickPort(), tcp.PickPort()
			commandPort := net.Port(0)
			if test.serverBinary == testBinaryPath {
				commandPort = tcp.PickPort()
			}
			serverConfig, clientConfig := wireGuardVersionSkewConfigs(destination, hostIP, serverPort, clientPort, commandPort)
			processes := make([]*exec.Cmd, 0, 2)
			t.Cleanup(func() { CloseAllServers(processes) })
			processes = append(processes, startReverseVersionSkewProcess(t, test.serverBinary, serverConfig))
			processes = append(processes, startReverseVersionSkewProcess(t, test.clientBinary, clientConfig))

			var lastErr error
			deadline := time.Now().Add(15 * time.Second)
			for {
				lastErr = testTCPConn(clientPort, 64*1024, 3*time.Second)()
				if lastErr == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("WireGuard path did not become ready: %v", lastErr)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if commandPort != 0 {
				connection := openVerifiedTCPConnection(t, clientPort)
				_, statsClient := dialStatsService(t, commandPort)
				waitStatsOnlineIPs(t, statsClient, "user>>>wireguard@example.com>>>online", hostIP.String())
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				waitStatsOnlineIPs(t, statsClient, "user>>>wireguard@example.com>>>online")
				CloseServer(processes[1])
				processes = processes[:1]
			}
		})
	}
}

func wireGuardHostIP(t *testing.T) netip.Addr {
	t.Helper()
	for _, address := range common.Must2(net.InterfaceAddrs()) {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			return prefix.Addr()
		}
	}
	t.Skip("WireGuard compatibility requires a non-loopback host address")
	return netip.Addr{}
}

func wireGuardVersionSkewConfigs(destination net.Destination, hostIP netip.Addr, serverPort, clientPort, commandPort net.Port) (*core.Config, *core.Config) {
	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	publicKey := func(private string) string {
		privateKey := common.Must2(wireguard.ParseKey(private))
		var public [32]byte
		curve25519.ScalarBaseMult(&public, privateKey)
		return hex.EncodeToString(public[:])
	}
	serverPublic, clientPublic := publicKey(serverPrivate), publicKey(clientPrivate)
	server := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}}, Listen: net.NewIPOrDomain(net.AnyIP)}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient: false, NoKernelTun: true, Endpoint: []string{"10.0.0.1"}, Mtu: 1420, SecretKey: serverPrivate,
				Users: []*protocol.User{{Email: "wireguard@example.com", Account: serial.ToTypedMessage(&wireguard.PeerConfig{PublicKey: clientPublic, AllowedIps: []string{"10.0.0.2/32"}})}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	if commandPort != 0 {
		enableVersionSkewStats(server, commandPort)
	}
	client := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}),
			ProxySettings:    serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(destination.Address), RewritePort: uint32(destination.Port), AllowedNetworks: []net.Network{net.Network_TCP}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{ProtocolName: "udp"}}),
			ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
				IsClient: true, NoKernelTun: false, Endpoint: []string{"10.0.0.2"}, Mtu: 1420, SecretKey: clientPrivate,
				Peers: []*wireguard.PeerConfig{{Endpoint: hostIP.String() + ":" + serverPort.String(), PublicKey: serverPublic, AllowedIps: []string{"0.0.0.0/0", "::0/0"}}},
			}),
		}},
	}
	return server, client
}

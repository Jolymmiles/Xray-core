//go:build integration

package scenarios

import (
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func TestLegacyMuxVersionSkew(t *testing.T) {
	testLegacyMuxVersionSkew(t, false)
}

func TestXUDPVersionSkew(t *testing.T) {
	testLegacyMuxVersionSkew(t, true)
}

func testLegacyMuxVersionSkew(t *testing.T, xudp bool) {
	if testing.Short() {
		t.Skip("process-level legacy Mux version-skew matrix")
	}
	common.Must(BuildXray())
	oldBinary := buildReverseCompatibilityBinary(t)
	for _, test := range []struct{ name, serverBinary, clientBinary string }{
		{"old-client-new-server", testBinaryPath, oldBinary},
		{"new-client-old-server", oldBinary, testBinaryPath},
		{"new-client-new-server", testBinaryPath, testBinaryPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			hostIP := wireGuardHostIP(t)
			tcpEcho := tcp.Server{MsgProcessor: xor, Listen: net.AnyIP}
			tcpDestination, err := tcpEcho.Start()
			common.Must(err)
			t.Cleanup(func() { _ = tcpEcho.Close() })
			tcpDestination.Address = net.IPAddress(hostIP.AsSlice())
			udpEcho := udp.Server{MsgProcessor: xor}
			udpDestination, err := udpEcho.Start()
			common.Must(err)
			t.Cleanup(func() { _ = udpEcho.Close() })

			serverPort, clientTCPPort, clientUDPPort := tcp.PickPort(), tcp.PickPort(), udp.PickPort()
			commandPort := net.Port(0)
			if test.serverBinary == testBinaryPath {
				commandPort = tcp.PickPort()
			}
			serverConfig, clientConfig := legacyMuxVersionSkewConfigs(tcpDestination, udpDestination, hostIP, serverPort, clientTCPPort, clientUDPPort, commandPort, xudp)
			commands := make([]*exec.Cmd, 0, 2)
			t.Cleanup(func() { CloseAllServers(commands) })
			commands = append(commands, startReverseVersionSkewProcess(t, test.serverBinary, serverConfig))
			commands = append(commands, startReverseVersionSkewProcess(t, test.clientBinary, clientConfig))

			deadline := time.Now().Add(15 * time.Second)
			for {
				tcpErr := testTCPConn(clientTCPPort, 64*1024, 2*time.Second)()
				udpErr := testUDPConn(clientUDPPort, 64*1024, 2*time.Second)()
				if tcpErr == nil && udpErr == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("legacy Mux path did not become ready (xudp=%v): tcp=%v udp=%v", xudp, tcpErr, udpErr)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if commandPort != 0 {
				connection := openVerifiedTCPConnection(t, clientTCPPort)
				_, statsClient := dialStatsService(t, commandPort)
				waitStatsOnlineIPs(t, statsClient, "user>>>mux@example.com>>>online", hostIP.String())
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				CloseServer(commands[1])
				commands = commands[:1]
				waitStatsOnlineIPs(t, statsClient, "user>>>mux@example.com>>>online")
			}
		})
	}
}

func legacyMuxVersionSkewConfigs(tcpDestination, udpDestination net.Destination, hostIP netip.Addr, serverPort, clientTCPPort, clientUDPPort, commandPort net.Port, xudp bool) (*core.Config, *core.Config) {
	id := uuid.New()
	userID := protocol.NewID(id)
	server := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}}, Listen: net.NewIPOrDomain(net.AnyIP)}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{User: []*protocol.User{{
				Email:   "mux@example.com",
				Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String()}),
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	if commandPort != 0 {
		enableVersionSkewStats(server, commandPort)
	}
	xudpConcurrency := int32(0)
	if xudp {
		xudpConcurrency = 4
	}
	client := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientTCPPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(tcpDestination.Address), RewritePort: uint32(tcpDestination.Port), AllowedNetworks: []net.Network{net.Network_TCP}})},
			{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientUDPPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(udpDestination.Address), RewritePort: uint32(udpDestination.Port), AllowedNetworks: []net.Network{net.Network_UDP}})},
		},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4, XudpConcurrency: xudpConcurrency}}),
			ProxySettings:  serial.ToTypedMessage(&outbound.Config{Receiver: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.IPAddress(hostIP.AsSlice())), Port: uint32(serverPort), User: &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String(), SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})}}}),
		}},
	}
	return server, client
}

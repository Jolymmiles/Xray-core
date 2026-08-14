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

func TestDirectVersionSkew(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level direct version-skew matrix")
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
			serverConfig, clientConfig := directVersionSkewConfigs(tcpDestination, udpDestination, hostIP, serverPort, clientTCPPort, clientUDPPort, commandPort)
			processes := make([]*exec.Cmd, 0, 2)
			t.Cleanup(func() { CloseAllServers(processes) })
			processes = append(processes, startReverseVersionSkewProcess(t, test.serverBinary, serverConfig))
			processes = append(processes, startReverseVersionSkewProcess(t, test.clientBinary, clientConfig))

			deadline := time.Now().Add(15 * time.Second)
			for {
				tcpErr := testTCPConn(clientTCPPort, 64*1024, 2*time.Second)()
				udpErr := testUDPConn(clientUDPPort, 64*1024, 2*time.Second)()
				if tcpErr == nil && udpErr == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("direct path did not become ready: tcp=%v udp=%v", tcpErr, udpErr)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if commandPort != 0 {
				connection := openVerifiedTCPConnection(t, clientTCPPort)
				_, statsClient := dialStatsService(t, commandPort)
				waitStatsOnlineIPs(t, statsClient, "user>>>direct@example.com>>>online", hostIP.String())
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				CloseServer(processes[1])
				processes = processes[:1]
				waitStatsOnlineIPs(t, statsClient, "user>>>direct@example.com>>>online")
			}
		})
	}
}

func directVersionSkewConfigs(tcpDestination, udpDestination net.Destination, hostIP netip.Addr, serverPort, clientTCPPort, clientUDPPort, commandPort net.Port) (*core.Config, *core.Config) {
	userID := protocol.NewID(uuid.New())
	server := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}}, Listen: net.NewIPOrDomain(net.AnyIP)}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{User: []*protocol.User{{
				Email:   "direct@example.com",
				Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String()}),
			}}}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
	}
	if commandPort != 0 {
		enableVersionSkewStats(server, commandPort)
	}
	client := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientTCPPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(tcpDestination.Address), RewritePort: uint32(tcpDestination.Port), AllowedNetworks: []net.Network{net.Network_TCP}})},
			{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientUDPPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(udpDestination.Address), RewritePort: uint32(udpDestination.Port), AllowedNetworks: []net.Network{net.Network_UDP}})},
		},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&outbound.Config{Receiver: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.IPAddress(hostIP.AsSlice())), Port: uint32(serverPort),
				User: &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String(), SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})},
			}}),
		}},
	}
	return server, client
}

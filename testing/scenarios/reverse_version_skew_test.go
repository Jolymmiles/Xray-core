//go:build integration

package scenarios

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"google.golang.org/protobuf/proto"
)

const reverseCompatibilityRevision = "816ae65180cc8e8ac6bac76ffcdbc561e93ebb7d" // v26.8.15

func TestReverseVersionSkew(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level reverse version-skew matrix")
	}
	common.Must(BuildXray())
	oldBinary := buildReverseCompatibilityBinary(t)
	for _, test := range []struct{ name, portalBinary, bridgeBinary string }{
		{"old-bridge-new-portal", testBinaryPath, oldBinary},
		{"new-bridge-old-portal", oldBinary, testBinaryPath},
		{"new-bridge-new-portal", testBinaryPath, testBinaryPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			hostIP := wireGuardHostIP(t)
			echo := tcp.Server{MsgProcessor: xor, Listen: net.AnyIP}
			destination, err := echo.Start()
			common.Must(err)
			t.Cleanup(func() { _ = echo.Close() })
			destination.Address = net.IPAddress(hostIP.AsSlice())
			userID := protocol.NewID(uuid.New())
			externalPort, reversePort := tcp.PickPort(), tcp.PickPort()
			commandPort := net.Port(0)
			if test.portalBinary == testBinaryPath {
				commandPort = tcp.PickPort()
			}
			portal, bridge := reverseVersionSkewConfigs(destination, userID, hostIP, externalPort, reversePort, commandPort)
			processes := make([]*exec.Cmd, 0, 2)
			t.Cleanup(func() { CloseAllServers(processes) })
			processes = append(processes, startReverseVersionSkewProcess(t, test.portalBinary, portal))
			processes = append(processes, startReverseVersionSkewProcess(t, test.bridgeBinary, bridge))
			var lastErr error
			deadline := time.Now().Add(10 * time.Second)
			for {
				lastErr = testTCPConn(externalPort, 64*1024, 2*time.Second)()
				if lastErr == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("reverse path did not become ready: %v", lastErr)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if commandPort != 0 {
				connection := openVerifiedTCPConnection(t, externalPort)
				_, statsClient := dialStatsService(t, commandPort)
				waitStatsOnlineIPs(t, statsClient, "user>>>reverse@example.com>>>online", hostIP.String())
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				CloseServer(processes[1])
				processes = processes[:1]
				waitStatsOnlineIPs(t, statsClient, "user>>>reverse@example.com>>>online")
			}
		})
	}
}

func buildReverseCompatibilityBinary(t *testing.T) string {
	t.Helper()
	source, binary := t.TempDir(), filepath.Join(t.TempDir(), "xray-old")
	archive := exec.Command("git", "-C", filepath.Join("..", ".."), "archive", reverseCompatibilityRevision)
	extract := exec.Command("tar", "-x", "-C", source)
	pipe, err := archive.StdoutPipe()
	common.Must(err)
	extract.Stdin, archive.Stderr, extract.Stderr = pipe, os.Stderr, os.Stderr
	common.Must(extract.Start())
	common.Must(archive.Run())
	common.Must(extract.Wait())
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./main")
	build.Dir, build.Stdout, build.Stderr = source, os.Stdout, os.Stderr
	common.Must(build.Run())
	return binary
}

func startReverseVersionSkewProcess(t *testing.T, binary string, config *core.Config) *exec.Cmd {
	t.Helper()
	encoded, err := proto.Marshal(withDefaultApps(config))
	common.Must(err)
	process := exec.Command(binary, "-config=stdin:", "-format=pb")
	process.Stdin, process.Stdout, process.Stderr = bytes.NewReader(encoded), os.Stdout, os.Stderr
	common.Must(process.Start())
	return process
}

func reverseVersionSkewConfigs(destination net.Destination, userID *protocol.ID, hostIP netip.Addr, externalPort, reversePort, commandPort net.Port) (*core.Config, *core.Config) {
	portal := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&reverse.Config{PortalConfig: []*reverse.PortalConfig{{Tag: "portal", Domain: "test.example.com"}}}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
				{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "test.example.com"}}}}, TargetTag: &router.RoutingRule_Tag{Tag: "portal"}},
				{InboundTag: []string{"external"}, TargetTag: &router.RoutingRule_Tag{Tag: "portal"}},
			}}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{Tag: "external", ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(externalPort)}}, Listen: net.NewIPOrDomain(net.LocalHostIP)}), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(destination.Address), RewritePort: uint32(destination.Port), AllowedNetworks: []net.Network{net.Network_TCP}})},
			{ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(reversePort)}}, Listen: net.NewIPOrDomain(net.AnyIP)}), ProxySettings: serial.ToTypedMessage(&inbound.Config{User: []*protocol.User{{Email: "reverse@example.com", Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String()})}}})},
		},
		Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&blackhole.Config{})}},
	}
	if commandPort != 0 {
		enableVersionSkewStats(portal, commandPort)
	}
	bridge := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&reverse.Config{BridgeConfig: []*reverse.BridgeConfig{{Tag: "bridge", Domain: "test.example.com"}}}),
			serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{
				{Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "test.example.com"}}}}, TargetTag: &router.RoutingRule_Tag{Tag: "reverse"}},
				{InboundTag: []string{"bridge"}, TargetTag: &router.RoutingRule_Tag{Tag: "freedom"}},
			}}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "freedom", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})},
			{Tag: "reverse", ProxySettings: serial.ToTypedMessage(&outbound.Config{Receiver: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.IPAddress(hostIP.AsSlice())), Port: uint32(reversePort), User: &protocol.User{Account: serial.ToTypedMessage(&vmess.Account{Id: userID.String(), SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}})}}})},
		},
	}
	return portal, bridge
}

package scenarios

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
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
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func wireguardPublicKey(private string) string {
	key, err := wireguard.ParseKey(private)
	common.Must(err)
	var public [32]byte
	curve25519.ScalarBaseMult(&public, key)
	return hex.EncodeToString(public[:])
}

func TestWireguard(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	udpServer := udp.Server{
		MsgProcessor: xor,
	}
	udpDest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")

	// What the client asks for is somewhere else, the stack of the server takes nothing that is for this machine.
	redirect := func(tag string, dest net.Destination) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(dest.Address),
						Port:    uint32(dest.Port),
					},
				},
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}
	}
	serverPort := udp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{Networks: []net.Network{net.Network_TCP}, TargetTag: &router.RoutingRule_Tag{Tag: "tcp"}},
					{Networks: []net.Network{net.Network_UDP}, TargetTag: &router.RoutingRule_Tag{Tag: "udp"}},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:  false,
					Endpoint:  []string{"10.0.0.1", "fd00::1"},
					Mtu:       1420,
					SecretKey: serverPrivate,
					Users: []*protocol.User{{
						Email: "love@xray.com",
						Account: serial.ToTypedMessage(&wireguard.PeerConfig{
							PublicKey:  wireguardPublicKey(clientPrivate),
							AllowedIps: []string{"10.0.0.2/32", "fd00::2/128"},
						}),
					}},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			redirect("tcp", dest),
			redirect("udp", udpDest),
		},
	}

	tcpPorts := pickVersionSkewTCPPorts(t, 2)
	clientPort, client6Port := tcpPorts[0], tcpPorts[1]
	clientUDPPort := udp.PickPort()
	dokodemoInbound := func(port net.Port, dest net.Destination) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{dest.Network},
			}),
		}
	}
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			dokodemoInbound(clientPort, net.TCPDestination(net.ParseAddress("192.0.2.1"), 7)),
			dokodemoInbound(client6Port, net.TCPDestination(net.ParseAddress("2001:db8::1"), 7)),
			dokodemoInbound(clientUDPPort, net.UDPDestination(net.ParseAddress("192.0.2.1"), 7)),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    true,
					NoKernelTun: true,
					Endpoint:    []string{"10.0.0.2", "fd00::2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   "127.0.0.1:" + serverPort.String(),
						PublicKey:  wireguardPublicKey(serverPrivate),
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var errg errgroup.Group
	for range 3 {
		errg.Go(testTCPConn(clientPort, 1024*1024, time.Second*20))
	}
	errg.Go(testTCPConn(client6Port, 1024*1024, time.Second*20))
	errg.Go(testUDPConn(clientUDPPort, 1024, time.Second*5))
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
}

// TestWireguardOnlinePresence keeps the client in Xray's built-in TCP/IP
// stack and checks that the server reports the client's outer address online
// while it is connected. The tunnel reaches this host's own address: through a
// kernel TUN, used whenever the test has CAP_NET_ADMIN, the decrypted replies
// carry a local source address that Linux drops as martians, and the TUN would
// add a device and rewrite sysctls of the host's network namespace.
// TestWireguardKernelTun covers the kernel TUN client in a network namespace of
// its own.
func TestWireguardOnlinePresence(t *testing.T) {
	runWireguardScenario(t, true, nil)
}

// runWireguardScenario tunnels TCP from a WireGuard client to a WireGuard
// server, both Xray processes, and on to an echo server on this host's own
// address. clientNoKernelTun selects the client's network stack, and
// whileConnected, when set, runs after the traffic while both are still up.
func runWireguardScenario(t *testing.T, clientNoKernelTun bool, whileConnected func(*testing.T)) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
		Listen:       net.AnyIP,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	for _, address := range common.Must2(net.InterfaceAddrs()) {
		prefix, parseErr := netip.ParsePrefix(address.String())
		if parseErr == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			dest.Address = net.IPAddress(prefix.Addr().AsSlice())
			break
		}
	}
	if dest.Address.IP().IsLoopback() || dest.Address.IP().IsUnspecified() {
		t.Skip("WireGuard interop requires a non-loopback host address")
	}

	serverPrivate, _ := conf.ParseWireGuardKey("EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10=")
	clientPrivate, _ := conf.ParseWireGuardKey("CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I=")
	publicKey := func(private string) string {
		privateKey, err := wireguard.ParseKey(private)
		if err != nil {
			t.Fatal(err)
		}
		var public [32]byte
		curve25519.ScalarBaseMult(&public, privateKey)
		return hex.EncodeToString(public[:])
	}
	serverPublic := publicKey(serverPrivate)
	clientPublic := publicKey(clientPrivate)
	for name, key := range map[string]string{"server private": serverPrivate, "server public": serverPublic, "client private": clientPrivate, "client public": clientPublic} {
		if len(key) != 64 {
			t.Fatalf("%s key length = %d", name, len(key))
		}
	}

	serverPort := udp.PickPort()
	tcpPorts := pickVersionSkewTCPPorts(t, 2)
	commandPort := tcpPorts[0]
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{Level: map[uint32]*policy.Policy{
				0: {Stats: &policy.Policy_Stats{UserOnline: true}},
			}}),
			serial.ToTypedMessage(&commander.Config{
				Tag:    "api",
				Listen: fmt.Sprintf("127.0.0.1:%d", commandPort),
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&statscmd.Config{}),
				},
			}),
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.AnyIP),
				}),
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    false,
					NoKernelTun: true,
					Endpoint:    []string{"10.0.0.1"},
					Mtu:         1420,
					SecretKey:   serverPrivate,
					Users: []*protocol.User{{
						Email: "wireguard@example.com",
						Account: serial.ToTypedMessage(&wireguard.PeerConfig{
							PublicKey:  clientPublic,
							AllowedIps: []string{"10.0.0.2/32"},
						}),
					}},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			},
		},
	}
	serverDevice, err := serverConfig.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	memoryUser, err := serverDevice.(*wireguard.DeviceConfig).Users[0].ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	wantClientPublic, err := wireguard.ParseKey(clientPublic)
	if err != nil || memoryUser.Account.(*wireguard.MemoryAccount).Pub != *wantClientPublic {
		t.Fatal("wireguard server user key did not survive configuration")
	}

	clientPort := tcpPorts[1]
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&wireguard.DeviceConfig{
					IsClient:    true,
					NoKernelTun: clientNoKernelTun,
					Endpoint:    []string{"10.0.0.2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   dest.Address.IP().String() + ":" + serverPort.String(),
						PublicKey:  serverPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)
	commandConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", commandPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	defer commandConn.Close()
	statsClient := statscmd.NewStatsServiceClient(commandConn)

	connection, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.LocalHostIP.IP(), Port: int(clientPort)})
	common.Must(err)
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("wireguard-presence")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	const onlineMetric = "user>>>wireguard@example.com>>>online"
	online, err := statsClient.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: onlineMetric})
	if err != nil {
		t.Fatal(err)
	}
	wantOuterIP := dest.Address.IP().String()
	if len(online.Ips) != 1 {
		t.Fatalf("online IPs = %v, want only %s", online.Ips, wantOuterIP)
	}
	if _, found := online.Ips[wantOuterIP]; !found {
		t.Fatalf("online IPs = %v, want %s", online.Ips, wantOuterIP)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		online, err = statsClient.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: onlineMetric})
		if err == nil && len(online.Ips) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("online IPs after close = %v, error %v", online.GetIps(), err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var errg errgroup.Group
	for range 4 {
		errg.Go(testTCPConn(clientPort, 1024, time.Second*5))
	}
	if err := errg.Wait(); err != nil {
		t.Error(err)
	}
	if whileConnected != nil {
		whileConnected(t)
	}
}

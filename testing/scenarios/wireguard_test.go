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

func TestWireguard(t *testing.T) {
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
	commandPort := tcp.PickPort()
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

	clientPort := tcp.PickPort()
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
					NoKernelTun: false,
					Endpoint:    []string{"10.0.0.2"},
					Mtu:         1420,
					SecretKey:   clientPrivate,
					Peers: []*wireguard.PeerConfig{{
						Endpoint:   dest.Address.IP().String() + ":" + serverPort.String(),
						PublicKey:  serverPublic,
						AllowedIps: []string{"0.0.0.0/0", "::0/0"},
					}},
				}),
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
}

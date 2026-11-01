package scenarios

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	revokedConnectionWait = 5 * time.Second
	revokeAPIWait         = 10 * time.Second // bounds the API dial and each call
)

func revokePolicy() *serial.TypedMessage {
	return serial.ToTypedMessage(&policy.Config{
		Level: map[uint32]*policy.Policy{
			0: {
				Timeout: &policy.Policy_Timeout{
					UplinkOnly:   &policy.Second{Value: 0},
					DownlinkOnly: &policy.Second{Value: 0},
				},
			},
		},
	})
}

// revokeClientConfig forwards clientPort through a VMess client of id to the
// server on serverPort, which connects to dest.
func revokeClientConfig(clientPort, serverPort net.Port, dest net.Destination, id *protocol.ID) *core.Config {
	return &core.Config{
		App: []*serial.TypedMessage{revokePolicy()},
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
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: id.String(),
								SecuritySettings: &protocol.SecurityConfig{
									Type: protocol.SecurityType_AES128_GCM,
								},
							}),
						},
					},
				}),
			},
		},
	}
}

func dialRevokeClient(t *testing.T, port net.Port) net.Conn {
	t.Helper()
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func requireEcho(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	if err := testTCPConn2(conn, 1024, revokedConnectionWait)(); err != nil {
		t.Fatalf("%s: no echo: %v", name, err)
	}
}

func requireConnectionEnded(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(revokedConnectionWait)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("%s: still open %v after RemoveUser", name, revokedConnectionWait)
		}
	}
}

func TestCommanderRemoveUserClosesItsConnections(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	const victimEmail = "victim@example.com"
	victimID := protocol.NewID(uuid.New())
	bystanderID := protocol.NewID(uuid.New())

	tcpPorts := pickVersionSkewTCPPorts(t, 4)
	cmdPort, serverPort := tcpPorts[0], tcpPorts[1]
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&commander.Config{
				Tag: "api",
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&command.Config{}),
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						InboundTag: []string{"api"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "api",
						},
					},
				},
			}),
			revokePolicy(),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "v",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					User: []*protocol.User{
						{
							Email:   victimEmail,
							Account: serial.ToTypedMessage(&vmess.Account{Id: victimID.String()}),
						},
						{
							Email:   "bystander@example.com",
							Account: serial.ToTypedMessage(&vmess.Account{Id: bystanderID.String()}),
						},
					},
				}),
			},
			{
				Tag: "api",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(cmdPort)}},
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	victimPort, bystanderPort := tcpPorts[2], tcpPorts[3]
	servers, err := InitializeServerConfigs(
		serverConfig,
		revokeClientConfig(victimPort, serverPort, dest, victimID),
		revokeClientConfig(bystanderPort, serverPort, dest, bystanderID),
	)
	common.Must(err)
	defer CloseAllServers(servers)

	waitForTCPPath(t, victimPort, 1024, 20*time.Second)
	waitForTCPPath(t, bystanderPort, 1024, 20*time.Second)

	victims := []net.Conn{dialRevokeClient(t, victimPort), dialRevokeClient(t, victimPort)}
	for i, conn := range victims {
		requireEcho(t, conn, fmt.Sprint("victim connection ", i, " before removal"))
	}
	bystander := dialRevokeClient(t, bystanderPort)
	requireEcho(t, bystander, "bystander before removal")

	dialCtx, cancelDial := context.WithTimeout(context.Background(), revokeAPIWait)
	cmdConn, err := grpc.DialContext(dialCtx, fmt.Sprintf("127.0.0.1:%d", cmdPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	cancelDial()
	if err != nil {
		t.Fatal(err)
	}
	defer cmdConn.Close()
	hsClient := command.NewHandlerServiceClient(cmdConn)

	removeCtx, cancelRemove := context.WithTimeout(context.Background(), revokeAPIWait)
	defer cancelRemove()
	if _, err := hsClient.AlterInbound(removeCtx, &command.AlterInboundRequest{
		Tag:       "v",
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: victimEmail}),
	}); err != nil {
		t.Fatal(err)
	}

	for i, conn := range victims {
		requireConnectionEnded(t, conn, fmt.Sprint("victim connection ", i))
	}
	requireEcho(t, bystander, "bystander after removal")

	addCtx, cancelAdd := context.WithTimeout(context.Background(), revokeAPIWait)
	defer cancelAdd()
	if _, err := hsClient.AlterInbound(addCtx, &command.AlterInboundRequest{
		Tag: "v",
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   victimEmail,
				Account: serial.ToTypedMessage(&vmess.Account{Id: victimID.String()}),
			},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	waitForTCPPath(t, victimPort, 1024, 20*time.Second)
}

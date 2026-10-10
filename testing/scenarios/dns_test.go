package scenarios

import (
	"context"
	"fmt"
	gonet "net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	dns_proxy "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	xproxy "golang.org/x/net/proxy"
)

func TestResolveIP(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dns.Config{
				StaticHosts: []*dns.Config_HostMapping{
					{
						Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "google.com"}}},
						Ip:     [][]byte{dest.Address.IP()},
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{Ip: []byte{127, 0, 0, 0}, Prefix: 8},
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
					Accounts: map[string]string{
						"Test Account": "Test Password",
					},
					Address:    net.NewIPOrDomain(net.LocalHostIP),
					UdpEnabled: false,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag: "direct",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						SocketSettings: &internet.SocketConfig{
							DomainStrategy: internet.DomainStrategy_USE_IP,
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		noAuthDialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
		common.Must(err)
		conn, err := noAuthDialer.Dial("tcp", fmt.Sprintf("google.com:%d", dest.Port))
		common.Must(err)
		defer conn.Close()

		if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
			t.Error(err)
		}
	}
}

// TestDNSOutboundSendThroughOverXUDP sends DNS queries over XUDP to a server
// whose DNS outbound has sendThrough and passes every query to the upstream.
// The mux server marks XUDP sessions timeout-only, and the DNS outbound used
// to dial them with a context stripped of the session outbound, so the
// sendThrough dialer indexed an empty outbound list and panicked. The panic
// never reached the top of its goroutine: unwinding ran the session's
// termination, which waits for the connection lock the panicking dial held,
// so every query left two goroutines blocked and got no answer.
//
// The client side is a dokodemo-door feeding a SOCKS UDP inbound: SOCKS
// marks each packet with its destination, which gives the VLESS outbound an
// XUDP Global ID, and VLESS carries UDP to any port but 53 and 443 as XUDP.
func TestDNSOutboundSendThroughOverXUDP(t *testing.T) {
	upstreamConn, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	common.Must(err)
	upstreamStarted := make(chan struct{})
	upstream := &mdns.Server{
		PacketConn: upstreamConn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			ans := new(mdns.Msg)
			ans.SetReply(r)
			for _, q := range r.Question {
				if q.Qtype == mdns.TypeA {
					rr, err := mdns.NewRR(q.Name + " IN A 192.0.2.53")
					common.Must(err)
					ans.Answer = append(ans.Answer, rr)
				}
			}
			_ = w.WriteMsg(ans)
		}),
		NotifyStartedFunc: func() { close(upstreamStarted) },
	}
	served := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = upstream.ActivateAndServe()
		close(served)
	}()
	// Join the serve goroutine on every path. Closing the socket releases it
	// even when the server never started.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := upstream.ShutdownContext(ctx)
		_ = upstreamConn.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("upstream DNS server did not stop within 5s")
			return
		}
		select {
		case <-upstreamStarted:
			if shutdownErr != nil {
				t.Errorf("shut down upstream DNS server: %v", shutdownErr)
			}
			if serveErr != nil {
				t.Errorf("upstream DNS server: %v", serveErr)
			}
		default:
		}
	})
	select {
	case <-upstreamStarted:
	case <-served:
		t.Fatalf("upstream DNS server stopped before serving: %v", serveErr)
	case <-time.After(10 * time.Second):
		t.Fatal("upstream DNS server did not start within 10s")
	}
	upstreamDest := net.DestinationFromAddr(upstreamConn.LocalAddr())
	if upstreamDest.Port == 53 || upstreamDest.Port == 443 {
		t.Fatalf("upstream port %d is not carried as XUDP", upstreamDest.Port)
	}

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					Via: net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dns_proxy.Config{
					Rule: []*dns_proxy.DNSRuleConfig{{Action: dns_proxy.RuleAction_Direct}},
				}),
			},
		},
	}

	socksPort := tcp.PickPort()
	socksConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(socksPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType:   socks.AuthType_NO_AUTH,
					Address:    net.NewIPOrDomain(net.LocalHostIP),
					UdpEnabled: true,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
	}

	clientUDPPort := udp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientUDPPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(upstreamDest.Address),
					RewritePort:     uint32(upstreamDest.Port),
					AllowedNetworks: []net.Network{net.Network_UDP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&socks.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(socksPort),
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, socksConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	clientAddr := net.UDPDestination(net.LocalHostIP, clientUDPPort).NetAddr()
	exchange := func(name string, timeout time.Duration) error {
		query := new(mdns.Msg)
		query.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
		answer, _, err := (&mdns.Client{Net: "udp", Timeout: timeout}).Exchange(query, clientAddr)
		if err != nil {
			return err
		}
		if len(answer.Answer) != 1 {
			return fmt.Errorf("answer for %s has %d records, want 1: %v", name, len(answer.Answer), answer)
		}
		if a, ok := answer.Answer[0].(*mdns.A); !ok || a.A.String() != "192.0.2.53" {
			return fmt.Errorf("answer for %s is %v, want the upstream's 192.0.2.53", name, answer.Answer[0])
		}
		return nil
	}

	// Readiness is the first query answered through the whole client, XUDP,
	// server and upstream path; a session stuck in the dial never answers.
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := exchange("ready.example.com", min(time.Second, time.Until(deadline)))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DNS answer through XUDP within 20s: %v", err)
		}
	}
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if err := exchange(name, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
}

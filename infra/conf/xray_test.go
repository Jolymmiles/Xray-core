package conf_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

func TestXrayConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(Config)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"log": {
					"access": "/var/log/xray/access.log",
					"loglevel": "error",
					"error": "/var/log/xray/error.log"
				},
				"inbounds": [{
					"streamSettings": {
						"network": "ws",
						"wsSettings": {
							"host": "example.domain",
							"path": ""
						},
						"tlsSettings": {
							"alpn": "h2"
						},
						"security": "tls"
					},
					"protocol": "vmess",
					"port": "443-500",
					"settings": {
						"clients": [
							{
								"security": "aes-128-gcm",
								"id": "0cdf8a45-303d-4fed-9780-29aa7f54175e"
							}
						]
					}
				}],
				"routing": {
					"rules": [
						{
							"ip": [
								"10.0.0.0/8"
							],
							"outboundTag": "blocked"
						}
					]
				}
			}`,
			Parser: createParser(),
			Output: &core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&log.Config{
						ErrorLogType:  log.LogType_File,
						ErrorLogPath:  "/var/log/xray/error.log",
						ErrorLogLevel: clog.Severity_Error,
						AccessLogType: log.LogType_File,
						AccessLogPath: "/var/log/xray/access.log",
					}),
					serial.ToTypedMessage(&dispatcher.Config{}),
					serial.ToTypedMessage(&proxyman.InboundConfig{}),
					serial.ToTypedMessage(&proxyman.OutboundConfig{}),
					serial.ToTypedMessage(&router.Config{
						DomainStrategy: router.Config_AsIs,
						Rule: []*router.RoutingRule{
							{
								Ip: []*geodata.IPRule{
									{
										Value: &geodata.IPRule_Custom{
											Custom: &geodata.CIDRRule{
												Cidr: &geodata.CIDR{Ip: []byte{10, 0, 0, 0}, Prefix: 8},
											},
										},
									},
								},
								TargetTag: &router.RoutingRule_Tag{
									Tag: "blocked",
								},
							},
						},
					}),
				},
				Inbound: []*core.InboundHandlerConfig{
					{
						ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
							PortList: &net.PortList{Range: []*net.PortRange{{
								From: 443,
								To:   500,
							}}},
							StreamSettings: &internet.StreamConfig{
								ProtocolName: "websocket",
								TransportSettings: []*internet.TransportConfig{
									{
										ProtocolName: "websocket",
										Settings: serial.ToTypedMessage(&websocket.Config{
											Host: "example.domain",
										}),
									},
								},
								SecurityType: "xray.transport.internet.tls.Config",
								SecuritySettings: []*serial.TypedMessage{
									serial.ToTypedMessage(&tls.Config{
										NextProtocol: []string{"h2"},
									}),
								},
							},
						}),
						ProxySettings: serial.ToTypedMessage(&inbound.Config{
							User: []*protocol.User{
								{
									Level: 0,
									Account: serial.ToTypedMessage(&vmess.Account{
										Id: "0cdf8a45-303d-4fed-9780-29aa7f54175e",
										SecuritySettings: &protocol.SecurityConfig{
											Type: protocol.SecurityType_AES128_GCM,
										},
									}),
								},
							},
						}),
					},
				},
			},
		},
	})
}

func TestSniffingConfig_Build(t *testing.T) {
	config := &SniffingConfig{
		Enabled:         true,
		DestOverride:    StringList{"http", "tls"},
		DomainsExcluded: StringList{"full:api.example.com", "domain:blocked.example", "regexp:^test[0-9]+\\.internal$"},
		IPsExcluded:     StringList{"192.168.1.1", "2001:db8::/32"},
		MetadataOnly:    true,
		RouteOnly:       true,
	}

	built, err := config.Build()
	if err != nil {
		t.Fatalf("SniffingConfig.Build() failed: %v", err)
	}

	if !built.Enabled || !built.MetadataOnly || !built.RouteOnly {
		t.Fatalf("SniffingConfig.Build() lost sniffing flags: %+v", built)
	}
	if len(built.DestinationOverride) != 2 {
		t.Fatalf("SniffingConfig.Build() lost destination overrides: %+v", built.DestinationOverride)
	}
	if len(built.DomainsExcluded) != 3 {
		t.Fatalf("SniffingConfig.Build() produced %d domain rules", len(built.DomainsExcluded))
	}
	if len(built.IpsExcluded) != 2 {
		t.Fatalf("SniffingConfig.Build() produced %d ip rules", len(built.IpsExcluded))
	}

	want := []struct {
		ruleType geodata.Domain_Type
		value    string
	}{
		{ruleType: geodata.Domain_Full, value: "api.example.com"},
		{ruleType: geodata.Domain_Domain, value: "blocked.example"},
		{ruleType: geodata.Domain_Regex, value: "^test[0-9]+\\.internal$"},
	}
	for i, tc := range want {
		rule := built.DomainsExcluded[i].GetCustom()
		if rule == nil {
			t.Fatalf("SniffingConfig.Build() produced a non-custom rule at index %d", i)
		}
		if rule.Type != tc.ruleType || rule.Value != tc.value {
			t.Fatalf("SniffingConfig.Build() produced wrong rule at index %d: got (%v, %q), want (%v, %q)", i, rule.Type, rule.Value, tc.ruleType, tc.value)
		}
	}

	wantIPs := []struct {
		ip     []byte
		prefix uint32
	}{
		{ip: []byte(net.ParseAddress("192.168.1.1").IP()), prefix: 32},
		{ip: []byte(net.ParseAddress("2001:db8::").IP()), prefix: 32},
	}
	for i, tc := range wantIPs {
		rule := built.IpsExcluded[i].GetCustom()
		if rule == nil {
			t.Fatalf("SniffingConfig.Build() produced a non-custom ip rule at index %d", i)
		}
		cidr := rule.GetCidr()
		if cidr == nil {
			t.Fatalf("SniffingConfig.Build() produced a custom ip rule without cidr at index %d", i)
		}
		if !reflect.DeepEqual(cidr.Ip, tc.ip) || cidr.Prefix != tc.prefix {
			t.Fatalf("SniffingConfig.Build() produced wrong ip rule at index %d: got (%v, %d), want (%v, %d)", i, cidr.Ip, cidr.Prefix, tc.ip, tc.prefix)
		}
	}
}

func TestMuxConfig_Build(t *testing.T) {
	tests := []struct {
		name   string
		fields string
		want   *proxyman.MultiplexingConfig
	}{
		{"default", `{"enabled": true, "concurrency": 16}`, &proxyman.MultiplexingConfig{
			Enabled:         true,
			Concurrency:     16,
			XudpConcurrency: 0,
			XudpProxyUDP443: "reject",
		}},
		{"empty def", `{}`, &proxyman.MultiplexingConfig{
			Enabled:         false,
			Concurrency:     0,
			XudpConcurrency: 0,
			XudpProxyUDP443: "reject",
		}},
		{"not enable", `{"enabled": false, "concurrency": 4}`, &proxyman.MultiplexingConfig{
			Enabled:         false,
			Concurrency:     4,
			XudpConcurrency: 0,
			XudpProxyUDP443: "reject",
		}},
		{"forbidden", `{"enabled": false, "concurrency": -1}`, &proxyman.MultiplexingConfig{
			Enabled:         false,
			Concurrency:     -1,
			XudpConcurrency: 0,
			XudpProxyUDP443: "reject",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MuxConfig{}
			common.Must(json.Unmarshal([]byte(tt.fields), m))
			if got, _ := m.Build(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MuxConfig.Build() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSMuxLogicalHalfCloseConfig(t *testing.T) {
	var config SMuxConfig
	if err := json.Unmarshal([]byte("{\"enabled\":true,\"protocol\":\"smux\",\"logicalHalfClose\":\"require\"}"), &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.LogicalHalfClose != "require" {
		t.Fatalf("logical half-close = %q, want require", built.LogicalHalfClose)
	}
	for _, invalid := range []SMuxConfig{
		{Enabled: true, Protocol: "smux", LogicalHalfClose: "invalid"},
		{Enabled: true, Protocol: "h2mux", LogicalHalfClose: "auto"},
	} {
		if _, err := invalid.Build(); err == nil {
			t.Fatalf("invalid config %#v was accepted", invalid)
		}
	}
}

func TestSMuxConfigBuild(t *testing.T) {
	tests := []struct {
		name    string
		fields  string
		want    *proxyman.SmuxConfig
		wantErr bool
	}{
		{
			name:   "defaults to smux",
			fields: `{}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
			},
		},
		{
			name: "all options",
			fields: `{
				"enabled": true,
				"protocol": "smux",
				"maxConnections": 4,
				"minStreams": 8,
				"padding": true,
				"onlyTcp": true
			}`,
			want: &proxyman.SmuxConfig{
				Enabled:        true,
				Protocol:       "smux",
				MaxConnections: 4,
				MinStreams:     8,
				Padding:        true,
				OnlyTcp:        true,
			},
		},
		{
			name: "brutal options",
			fields: `{
				"enabled": true,
				"brutal-opts": {
					"enabled": true,
					"up": "100 Mbps",
					"down": "100 Mbps"
				}
			}`,
			want: &proxyman.SmuxConfig{
				Enabled:  true,
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					Enabled: true,
					UpBps:   12_500_000,
					DownBps: 12_500_000,
				},
			},
		},
		{
			name: "brutal bare Mbps",
			fields: `{
				"brutal-opts": {
					"enabled": true,
					"up": "100",
					"down": "100"
				}
			}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					Enabled: true,
					UpBps:   12_500_000,
					DownBps: 12_500_000,
				},
			},
		},
		{
			name:   "brutal prefixes and byte units",
			fields: `{"brutal-opts":{"up":"1 Kbps","down":"1 TBps"}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					UpBps:   125,
					DownBps: 1_000_000_000_000,
				},
			},
		},
		{
			name:   "brutal giga prefix",
			fields: `{"brutal-opts":{"up":"1 Gbps","down":"1 GBps"}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					UpBps:   125_000_000,
					DownBps: 1_000_000_000,
				},
			},
		},
		{
			name:   "brutal large bit rate",
			fields: `{"brutal-opts":{"enabled":true,"up":"20000000 Tbps","down":"20000000 Tbps"}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					Enabled: true,
					UpBps:   2_500_000_000_000_000_000,
					DownBps: 2_500_000_000_000_000_000,
				},
			},
		},
		{
			name:   "brutal minimum bits and bytes",
			fields: `{"brutal-opts":{"enabled":true,"up":"525 Kbps","down":"65536 Bps"}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					Enabled: true,
					UpBps:   65_625,
					DownBps: 65_536,
				},
			},
		},
		{
			name:   "brutal disabled",
			fields: `{"brutal-opts":{"enabled":false}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal:   &proxyman.BrutalConfig{},
			},
		},
		{
			name:    "brutal decimal rate",
			fields:  `{"brutal-opts":{"enabled":true,"up":"100.5 Mbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal negative rate",
			fields:  `{"brutal-opts":{"enabled":true,"up":"-1 Mbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal rate below minimum",
			fields:  `{"brutal-opts":{"enabled":true,"up":"1 Mbps","down":"64 KBps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal invalid unit",
			fields:  `{"brutal-opts":{"enabled":true,"up":"100 MB","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal lowercase prefix",
			fields:  `{"brutal-opts":{"enabled":true,"up":"100 mbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal leading whitespace",
			fields:  `{"brutal-opts":{"enabled":true,"up":" 100 Mbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal trailing whitespace",
			fields:  `{"brutal-opts":{"enabled":true,"up":"100 Mbps ","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "brutal unicode separator",
			fields:  `{"brutal-opts":{"enabled":true,"up":"100\u00a0Mbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:   "brutal ASCII tab separator",
			fields: `{"brutal-opts":{"enabled":true,"up":"100\tMbps","down":"100 Mbps"}}`,
			want: &proxyman.SmuxConfig{
				Protocol: "smux",
				Brutal: &proxyman.BrutalConfig{
					Enabled: true,
					UpBps:   12_500_000,
					DownBps: 12_500_000,
				},
			},
		},
		{
			name:    "brutal overflow",
			fields:  `{"brutal-opts":{"enabled":true,"up":"18446744073709551615 Tbps","down":"100 Mbps"}}`,
			wantErr: true,
		},
		{
			name:    "unknown protocol",
			fields:  `{"enabled":true,"protocol":"xray"}`,
			wantErr: true,
		},
		{
			name:    "yamux belongs to a later stage",
			fields:  `{"enabled":true,"protocol":"yamux"}`,
			wantErr: true,
		},
		{
			name:   "h2mux",
			fields: `{"enabled":true,"protocol":"h2mux"}`,
			want: &proxyman.SmuxConfig{
				Enabled:  true,
				Protocol: "h2mux",
			},
		},
		{
			name:    "negative pool limit",
			fields:  `{"enabled":true,"maxConnections":-1}`,
			wantErr: true,
		},
		{
			name:    "conflicting pool modes",
			fields:  `{"enabled":true,"maxConnections":2,"maxStreams":8}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SMuxConfig{}
			common.Must(json.Unmarshal([]byte(tt.fields), config))
			got, err := config.Build()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			common.Must(err)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SMuxConfig.Build() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestInboundSMuxConfigBuild(t *testing.T) {
	tests := []struct {
		name    string
		fields  string
		want    *proxyman.SmuxConfig
		wantErr bool
	}{
		{
			name:   "disabled default",
			fields: `{}`,
			want:   &proxyman.SmuxConfig{},
		},
		{
			name:   "independent limits",
			fields: `{"brutal-opts":{"enabled":true,"up":"800 Mbps","down":"1 Gbps"}}`,
			want: &proxyman.SmuxConfig{Brutal: &proxyman.BrutalConfig{
				Enabled: true,
				UpBps:   100_000_000,
				DownBps: 125_000_000,
			}},
		},
		{
			name:    "below minimum",
			fields:  `{"brutal-opts":{"enabled":true,"up":"64 KBps","down":"1 Gbps"}}`,
			wantErr: true,
		},
		{
			name:   "h2mux frame size omitted",
			fields: `{"brutal-opts":{"enabled":false}}`,
			want:   &proxyman.SmuxConfig{Brutal: &proxyman.BrutalConfig{}},
		},
		{
			name:   "h2mux frame size protocol minimum",
			fields: `{"h2muxMaxReadFrameSize":16384}`,
			want:   &proxyman.SmuxConfig{H2MuxMaxReadFrameSize: 16384},
		},
		{
			name:   "h2mux frame size protocol maximum",
			fields: `{"h2muxMaxReadFrameSize":16777215}`,
			want:   &proxyman.SmuxConfig{H2MuxMaxReadFrameSize: 16777215},
		},
		{
			name:   "h2mux frame size zero keeps the default",
			fields: `{"h2muxMaxReadFrameSize":0}`,
			want:   &proxyman.SmuxConfig{},
		},
		{
			name:    "h2mux frame size below protocol minimum",
			fields:  `{"h2muxMaxReadFrameSize":16383}`,
			wantErr: true,
		},
		{
			name:    "h2mux frame size above protocol maximum",
			fields:  `{"h2muxMaxReadFrameSize":16777216}`,
			wantErr: true,
		},
		{
			name:    "h2mux frame size negative",
			fields:  `{"h2muxMaxReadFrameSize":-1}`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config InboundSMuxConfig
			common.Must(json.Unmarshal([]byte(test.fields), &config))
			got, err := config.Build()
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			common.Must(err)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("InboundSMuxConfig.Build() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestInboundDetourCarriesSMuxBrutalIntoReceiverSettings(t *testing.T) {
	var config Config
	common.Must(json.Unmarshal([]byte(`{
		"inbounds": [{
			"protocol": "dokodemo-door",
			"port": 1234,
			"settings": {"address": "127.0.0.1", "port": 80, "network": "tcp"},
			"smux": {"brutal-opts": {"enabled": true, "up": "800 Mbps", "down": "1 Gbps"}}
		}]
	}`), &config))
	built, err := config.Build()
	common.Must(err)
	message, err := built.Inbound[0].ReceiverSettings.GetInstance()
	common.Must(err)
	receiver := message.(*proxyman.ReceiverConfig)
	want := &proxyman.SmuxConfig{Brutal: &proxyman.BrutalConfig{
		Enabled: true,
		UpBps:   100_000_000,
		DownBps: 125_000_000,
	}}
	if !reflect.DeepEqual(receiver.SmuxSettings, want) {
		t.Fatalf("receiver SMUX settings = %#v, want %#v", receiver.SmuxSettings, want)
	}
}

func TestInboundDetourCarriesSMuxH2MuxFrameSizeIntoReceiverSettings(t *testing.T) {
	var config Config
	common.Must(json.Unmarshal([]byte(`{
		"inbounds": [{
			"protocol": "dokodemo-door",
			"port": 1234,
			"settings": {"address": "127.0.0.1", "port": 80, "network": "tcp"},
			"smux": {"h2muxMaxReadFrameSize": 16384}
		}]
	}`), &config))
	built, err := config.Build()
	common.Must(err)
	message, err := built.Inbound[0].ReceiverSettings.GetInstance()
	common.Must(err)
	receiver := message.(*proxyman.ReceiverConfig)
	want := &proxyman.SmuxConfig{H2MuxMaxReadFrameSize: 16384}
	if !reflect.DeepEqual(receiver.SmuxSettings, want) {
		t.Fatalf("receiver SMUX settings = %#v, want %#v", receiver.SmuxSettings, want)
	}
}

func TestInboundDetourRejectsInvalidSMuxH2MuxFrameSize(t *testing.T) {
	var config Config
	common.Must(json.Unmarshal([]byte(`{
		"inbounds": [{
			"protocol": "dokodemo-door",
			"port": 1234,
			"settings": {"address": "127.0.0.1", "port": 80, "network": "tcp"},
			"smux": {"h2muxMaxReadFrameSize": 1024}
		}]
	}`), &config))
	if _, err := config.Build(); err == nil {
		t.Fatal("expected an error for an out-of-range h2muxMaxReadFrameSize")
	}
}

func TestConfig_Override(t *testing.T) {
	tests := []struct {
		name string
		orig *Config
		over *Config
		fn   string
		want *Config
	}{
		{
			"combine/empty",
			&Config{},
			&Config{
				LogConfig:    &LogConfig{},
				RouterConfig: &RouterConfig{},
				DNSConfig:    &DNSConfig{},
				Policy:       &PolicyConfig{},
				API:          &APIConfig{},
				Stats:        &StatsConfig{},
				Reverse:      &ReverseConfig{},
			},
			"",
			&Config{
				LogConfig:    &LogConfig{},
				RouterConfig: &RouterConfig{},
				DNSConfig:    &DNSConfig{},
				Policy:       &PolicyConfig{},
				API:          &APIConfig{},
				Stats:        &StatsConfig{},
				Reverse:      &ReverseConfig{},
			},
		},
		{
			"combine/newattr",
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "old"}}},
			&Config{LogConfig: &LogConfig{}}, "",
			&Config{LogConfig: &LogConfig{}, InboundConfigs: []InboundDetourConfig{{Tag: "old"}}},
		},
		{
			"replace/inbounds",
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}}},
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos1", Protocol: "kcp"}}},
			"",
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos0"}, {Tag: "pos1", Protocol: "kcp"}}},
		},
		{
			"replace/inbounds-replaceall",
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}}},
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos1", Protocol: "kcp"}, {Tag: "pos2", Protocol: "kcp"}}},
			"",
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos0"}, {Tag: "pos1", Protocol: "kcp"}, {Tag: "pos2", Protocol: "kcp"}}},
		},
		{
			"replace/notag-append",
			&Config{InboundConfigs: []InboundDetourConfig{{}, {Protocol: "vmess"}}},
			&Config{InboundConfigs: []InboundDetourConfig{{Tag: "pos1", Protocol: "kcp"}}},
			"",
			&Config{InboundConfigs: []InboundDetourConfig{{}, {Protocol: "vmess"}, {Tag: "pos1", Protocol: "kcp"}}},
		},
		{
			"replace/outbounds",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}}},
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos1", Protocol: "kcp"}}},
			"",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos0"}, {Tag: "pos1", Protocol: "kcp"}}},
		},
		{
			"replace/outbounds-prepend",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}, {Tag: "pos3"}}},
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos1", Protocol: "kcp"}, {Tag: "pos2", Protocol: "kcp"}, {Tag: "pos4", Protocol: "kcp"}}},
			"config.json",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos2", Protocol: "kcp"}, {Tag: "pos4", Protocol: "kcp"}, {Tag: "pos0"}, {Tag: "pos1", Protocol: "kcp"}, {Tag: "pos3"}}},
		},
		{
			"replace/outbounds-append",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}}},
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos2", Protocol: "kcp"}}},
			"config_tail.json",
			&Config{OutboundConfigs: []OutboundDetourConfig{{Tag: "pos0"}, {Protocol: "vmess", Tag: "pos1"}, {Tag: "pos2", Protocol: "kcp"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.orig.Override(tt.over, tt.fn)
			if r := cmp.Diff(tt.orig, tt.want); r != "" {
				t.Error(r)
			}
		})
	}
}

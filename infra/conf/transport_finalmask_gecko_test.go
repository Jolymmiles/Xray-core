package conf_test

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/wireguard"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// Gecko (salamander with packetSize) splits packets into chunks whose message
// ID repeats every 256 messages and no field ties a chunk to its message, so
// after a lost chunk the receiver can still deliver a packet spliced from two.
// It may only sit below whole-datagram integrity: a QUIC transport, or an
// mkcp-legacy integrity mask outside it (listed before it).
func TestGeckoRequiresDatagramIntegrity(t *testing.T) {
	const (
		gecko      = `{"type": "salamander", "settings": {"password": "gecko", "packetSize": "512-1200"}}`
		salamander = `{"type": "salamander", "settings": {"password": "plain"}}`
		checksum   = `{"type": "mkcp-legacy"}`
		aead       = `{"type": "mkcp-legacy", "settings": {"value": "seed"}}`
		dnsHeader  = `{"type": "mkcp-legacy", "settings": {"header": "dns"}}`
	)
	for _, tc := range []struct {
		name, network, masks string
		accept               bool
	}{
		{"hysteria", "hysteria", gecko, true},
		{"xhttp", "xhttp", gecko, true},
		{"masque", "masque", gecko, true},
		{"mkcp with the checksum mask outside", "kcp", checksum + "," + gecko, true},
		{"mkcp with the AEAD mask outside", "kcp", aead + "," + gecko, true},
		{"mkcp with xdns innermost", "kcp", aead + "," + gecko + "," + testXDNSMask, true},
		{"mkcp with plain salamander", "kcp", salamander, true},
		{"raw with plain salamander", "raw", salamander, true},
		{"raw with the checksum mask outside", "raw", checksum + "," + gecko, true},
		{"bare mkcp", "kcp", gecko, false},
		{"mkcp with the integrity mask inside", "kcp", gecko + "," + checksum, false},
		{"mkcp with a header that does not check integrity", "kcp", dnsHeader + "," + gecko, false},
		{"raw", "raw", gecko, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config StreamConfig
			if err := json.Unmarshal([]byte(`{"network": "`+tc.network+`", "finalmask": {"udp": [`+tc.masks+`]}}`), &config); err != nil {
				t.Fatal(err)
			}
			_, err := config.Build()
			switch {
			case tc.accept && err != nil:
				t.Fatalf("rejected: %v", err)
			case !tc.accept && err == nil:
				t.Fatal("accepted Gecko below a transport without datagram integrity")
			case !tc.accept && !strings.Contains(err.Error(), "packetSize"):
				t.Fatalf("error %q does not name packetSize", err)
			}
		})
	}
}

// A UDP inbound (the UDP hub) and WireGuard use their stream's UDP masks with
// no QUIC above them, whatever its network is. A nominal hysteria network
// passes the stream config check, so starting such an inbound must fail.
func TestRawUDPInboundsRefuseGeckoUnderNominalQUIC(t *testing.T) {
	const streamSettings = `{"network": "hysteria", "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "gecko", "packetSize": "512-1200"}}]}}`
	for _, tc := range []struct{ name, inbound string }{
		{"dokodemo-door UDP", `{"protocol": "dokodemo-door", "listen": "127.0.0.1", "port": %d, "settings": {"address": "127.0.0.1", "port": 53, "network": "udp"}, "streamSettings": ` + streamSettings + `}`},
		{"wireguard", `{"protocol": "wireguard", "listen": "127.0.0.1", "port": %d, "settings": {"secretKey": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "peers": [{"publicKey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "allowedIPs": ["10.0.0.2/32"]}]}, "streamSettings": ` + streamSettings + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := probe.LocalAddr().(*net.UDPAddr).Port
			probe.Close()

			var config Config
			raw := `{"inbounds": [` + fmt.Sprintf(tc.inbound, port) + `], "outbounds": [{"protocol": "freedom"}]}`
			if err := json.Unmarshal([]byte(raw), &config); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			instance, err := core.New(built)
			if err != nil {
				t.Fatalf("core.New: %v", err)
			}
			t.Cleanup(func() { instance.Close() })
			if err := instance.Start(); err == nil || !strings.Contains(err.Error(), "no QUIC above it") {
				t.Fatalf("Start = %v, want the raw UDP integrity error", err)
			}
		})
	}
}

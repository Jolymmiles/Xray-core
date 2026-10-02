package scenarios

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

func buildJSONConfig(t *testing.T, config string) *core.Config {
	t.Helper()
	jsonConfig, err := serial.DecodeJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	built, err := jsonConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	return built
}

// TestVLESSOverKCPOverXDNS runs a real Xray client and server with the xdns
// UDP mask under mKCP. The client reaches the server only through DNS
// queries sent to the resolver address, here the server itself.
func TestVLESSOverKCPOverXDNS(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	id := uuid.New().String()
	serverPort := udp.PickPort()
	clientPort := tcp.PickPort()
	// The kcp MTU stays below the TXT answer capacity for edns0 1232.
	const kcp = `"kcpSettings": {"mtu": 900, "tti": 20}`
	const domain = `{"name": "t.example.com", "types": [16], "edns0": 1232}`

	serverConfig := buildJSONConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "debug"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": "none"},
			"streamSettings": {"network": "kcp", %s,
				"finalmask": {"udp": [{"type": "xdns", "settings": {"domains": [%s]}}]}}
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
	}`, serverPort, id, kcp, domain))
	clientConfig := buildJSONConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "debug"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			"settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}
		}],
		"outbounds": [{
			"protocol": "vless",
			"settings": {"vnext": [{"address": "127.0.0.1", "port": %d, "users": [{"id": %q, "encryption": "none"}]}]},
			"streamSettings": {"network": "kcp", %s,
				"finalmask": {"udp": [{"type": "xdns", "settings": {
					"domains": [%s],
					"resolvers": [{"type": "udp", "settings": {"addr": "127.0.0.1:%d"}}]
				}}]}}
		}]
	}`, clientPort, dest.Port, serverPort, id, kcp, domain, serverPort))

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	for i := range 2 {
		if err := testTCPConn(clientPort, 4096, 30*time.Second)(); err != nil {
			t.Fatalf("connection %d through xdns: %v", i, err)
		}
	}
}

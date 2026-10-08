package scenarios

import (
	"fmt"
	stdnet "net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
)

// TestVLESSOverKCPOverXDNS runs a real Xray client and server with the xdns
// UDP mask under mKCP. The client reaches the server only through DNS queries
// sent to the resolver address, here the server itself. The VLESS address is
// a socket that never answers, so the traffic gets through only if xdns
// carries it, and nothing may reach that socket. From TaiLerV's
// sync/upstream-2026-10-02 branch (df84824f), adapted to the names/addrs
// schema.
func TestVLESSOverKCPOverXDNS(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()
	unanswered, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	common.Must(err)
	defer unanswered.Close()

	id := uuid.New().String()
	serverPort := udp.PickPort()
	clientPort := tcp.PickPort()
	// The kcp MTU stays below the TXT answer capacity for edns0 1232.
	const kcp = `"kcpSettings": {"mtu": 900, "tti": 20}`
	const domain = `{"names": ["t.example.com"], "types": [16], "edns0": 1232}`

	serverConfig := jsonCoreConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "debug"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": "none"},
			"streamSettings": {"network": "kcp", %s,
				"finalmask": {"udp": [{"type": "xdns", "settings": {"domains": [%s]}}]}}
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
	}`, serverPort, id, kcp, domain))
	clientConfig := jsonCoreConfig(t, fmt.Sprintf(`{
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
					"resolvers": [{"addrs": ["udp://127.0.0.1:%d"]}]
				}}]}}
		}]
	}`, clientPort, dest.Port, unanswered.LocalAddr().(*stdnet.UDPAddr).Port, id, kcp, domain, serverPort))

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	for i := range 2 {
		if err := testTCPConn(clientPort, 4096, 30*time.Second)(); err != nil {
			t.Fatalf("connection %d through xdns: %v", i, err)
		}
	}
	common.Must(unanswered.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
	if n, _, err := unanswered.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatalf("a %d-byte datagram reached the VLESS address around xdns", n)
	}
}

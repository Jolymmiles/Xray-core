package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdnet "net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/testing/servers/udp"
)

// jsonCoreConfig builds a core config from JSON, as `xray run` does.
func jsonCoreConfig(t *testing.T, config string) *core.Config {
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

// quicFirstFlight reads client datagrams captured by the Hysteria project;
// see common/protocol/quic/testdata/PROVENANCE.md.
func quicFirstFlight(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	datagrams := make([][]byte, n)
	for i := range datagrams {
		datagram, err := os.ReadFile(filepath.Join("..", "..", "common", "protocol", "quic", "testdata", prefix+"-"+strconv.Itoa(i)+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = datagram
	}
	return datagrams
}

// udpRecorder is a UDP destination that records every datagram it receives.
type udpRecorder struct {
	conn     *stdnet.UDPConn
	received chan []byte
}

// startUDPRecorder listens on a loopback UDP port and records every datagram
// it receives until the test ends.
func startUDPRecorder(t *testing.T) *udpRecorder {
	t.Helper()
	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &udpRecorder{conn: conn, received: make(chan []byte, 64)}
	go func() {
		defer close(recorder.received)
		for {
			datagram := make([]byte, 2048)
			n, _, err := conn.ReadFromUDP(datagram)
			if err != nil {
				return
			}
			recorder.received <- datagram[:n]
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return recorder
}

// port returns the UDP port the recorder listens on.
func (r *udpRecorder) port() int {
	return r.conn.LocalAddr().(*stdnet.UDPAddr).Port
}

// readinessProbe is the payload of the datagrams waitForUDPTunnel sends. It
// is not QUIC, so the server routes it to direct.
var readinessProbe = []byte("xray scenario readiness probe")

// waitForUDPTunnel sends probes through the client from a socket of their
// own until one reaches direct: the client then listens, and its Hysteria
// connection carries UDP to the server and on. A probe is sent every 100ms
// for up to 20s.
func waitForUDPTunnel(t *testing.T, clientPort int, direct *udpRecorder) {
	t.Helper()
	probe, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	client := &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: clientPort}
	resend := time.NewTicker(100 * time.Millisecond)
	defer resend.Stop()
	deadline := time.After(20 * time.Second)
	for {
		if _, err := probe.WriteToUDP(readinessProbe, client); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-direct.received:
			if !bytes.Equal(got, readinessProbe) {
				t.Fatalf("a %d-byte datagram that is not a probe reached direct", len(got))
			}
			return
		case <-resend.C:
		case <-deadline:
			t.Fatal("no probe crossed the tunnel within 20s")
		}
	}
}

// startQUICSniffingTunnel starts an Xray client that forwards UDP from the
// returned port to direct through an Xray Hysteria server. The server sniffs
// QUIC and routes flows whose server name ends in .sniff.test to sniffed. It
// returns once a probe has crossed the tunnel.
func startQUICSniffingTunnel(t *testing.T) (clientPort int, direct, sniffed *udpRecorder) {
	t.Helper()
	direct = startUDPRecorder(t)
	sniffed = startUDPRecorder(t)

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, keyPEM := certificate.ToPEM()
	pemLines := func(block []byte) string {
		return string(common.Must2(json.Marshal(strings.Split(strings.TrimSpace(string(block)), "\n"))))
	}
	serverPort := udp.PickPort()
	clientPort = int(udp.PickPort())
	const auth = "quic-sniffing"
	serverConfig := jsonCoreConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "hysteria",
			"settings": {"version": 2, "clients": [{"auth": %q, "email": "sniffing@example.test"}]},
			"streamSettings": {"network": "hysteria", "security": "tls",
				"tlsSettings": {"alpn": ["h3"], "certificates": [{"certificate": %s, "key": %s}]},
				"hysteriaSettings": {"version": 2}},
			"sniffing": {"enabled": true, "destOverride": ["quic"], "routeOnly": true}
		}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}},
			{"tag": "sniffed", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:%d", "finalRules": [{"action": "allow"}]}}
		],
		"routing": {"rules": [{"domain": ["regexp:\\.sniff\\.test$"], "outboundTag": "sniffed"}]}
	}`, serverPort, auth, pemLines(certificatePEM), pemLines(keyPEM), sniffed.port()))
	clientConfig := jsonCoreConfig(t, fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			"settings": {"address": "127.0.0.1", "port": %d, "network": "udp"}
		}],
		"outbounds": [{
			"protocol": "hysteria",
			"settings": {"version": 2, "address": "127.0.0.1", "port": %d},
			"streamSettings": {"network": "hysteria", "security": "tls",
				"tlsSettings": {"alpn": ["h3"], "serverName": "localhost", "pinnedPeerCertSha256": "%x"},
				"hysteriaSettings": {"version": 2, "auth": %q}}
		}]
	}`, clientPort, direct.port(), serverPort, certificateHash, auth))

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	t.Cleanup(func() { CloseAllServers(servers) })
	waitForUDPTunnel(t, clientPort, direct)
	return clientPort, direct, sniffed
}

// Hysteria 2.13.0 made sniffing find the server name of QUIC clients whose
// ClientHello spans several packets, so that domain rules apply to their
// traffic. Through an Xray Hysteria server that sniffs QUIC, each client's
// first flight must be routed by its server name and arrive unmodified. The
// flight is sent once, from a fresh socket, after a probe has crossed the
// tunnel, so a first flight that gets dropped fails the test instead of
// being sent again.
func TestHysteriaRoutesQUICBySniffedServerName(t *testing.T) {
	for _, flow := range []struct {
		name, prefix string
		datagrams    int
	}{
		{"Chrome 153", "quic-chrome153", 2},
		{"Firefox 153 ESR", "quic-firefox153esr", 2},
		{"curl 8.14 with OpenSSL 3.5", "quic-curl8.14-openssl3.5", 2},
		{"quiche", "quic-quiche", 3},
		{"ngtcp2 1.11", "quic-ngtcp2-1.11", 1},
		{"aioquic 1.2", "quic-aioquic1.2", 1},
	} {
		t.Run(flow.name, func(t *testing.T) {
			datagrams := quicFirstFlight(t, flow.prefix, flow.datagrams)
			clientPort, direct, sniffed := startQUICSniffingTunnel(t)
			conn, err := stdnet.DialUDP("udp", nil, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: clientPort})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for _, datagram := range datagrams {
				if _, err := conn.Write(datagram); err != nil {
					t.Fatal(err)
				}
			}

			// Hysteria relays UDP in unreliable QUIC datagrams, so a lost
			// datagram is reported apart from a modified or misrouted one.
			var viaSniffed, viaDirect [][]byte
			deadline := time.After(10 * time.Second)
		receive:
			for len(viaSniffed)+len(viaDirect) < len(datagrams) {
				select {
				case got := <-sniffed.received:
					viaSniffed = append(viaSniffed, got)
				case got := <-direct.received:
					if bytes.Equal(got, readinessProbe) {
						continue // a probe that arrived after the first one
					}
					viaDirect = append(viaDirect, got)
				case <-deadline:
					break receive
				}
			}
			for _, got := range slices.Concat(viaSniffed, viaDirect) {
				if !slices.ContainsFunc(datagrams, func(sent []byte) bool { return bytes.Equal(got, sent) }) {
					t.Errorf("a %d-byte datagram reached its destination modified", len(got))
				}
			}
			for i, sent := range datagrams {
				isSent := func(got []byte) bool { return bytes.Equal(got, sent) }
				switch {
				case slices.ContainsFunc(viaDirect, isSent):
					t.Errorf("datagram %d was routed without its sniffed server name", i)
				case !slices.ContainsFunc(viaSniffed, isSent):
					t.Errorf("datagram %d did not arrive within 10s; it may have been lost in transit", i)
				}
			}
		})
	}
}

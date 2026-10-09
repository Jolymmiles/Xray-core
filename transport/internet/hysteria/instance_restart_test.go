package hysteria_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet/hysteria"
)

// startJSONInstance starts an Xray instance in this process, as an embedding
// application does. stop closes it once; the test cleanup calls it too.
func startJSONInstance(t *testing.T, config string) (stop func()) {
	t.Helper()
	jsonConfig, err := serial.DecodeJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	built, err := jsonConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatal(err)
	}
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(stop)
	return stop
}

// XTLS/Xray-core#7100: an application that restarts its Xray instance in one
// process, such as a mobile client on every configuration change, kept one
// Hysteria connection per stopped instance open until the process exited.
// Each cycle starts a client instance, carries a payload from its inbound
// through a real Xray Hysteria server to an echo server, and stops it; one
// cleaner pass must then leave the process-wide pool as it found it.
func TestInstanceRestartsReleasePooledClients(t *testing.T) {
	echo := &tcp.Server{MsgProcessor: func(b []byte) []byte { return b }}
	echoDest, err := echo.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })

	certificate, certificateHash := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certificatePEM, keyPEM := certificate.ToPEM()
	pemLines := func(block []byte) string {
		lines, err := json.Marshal(strings.Split(strings.TrimSpace(string(block)), "\n"))
		if err != nil {
			t.Fatal(err)
		}
		return string(lines)
	}
	serverPort := udp.PickPort()
	const auth = "instance-restart"
	startJSONInstance(t, fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1", "port": %d, "protocol": "hysteria",
			"settings": {"version": 2, "clients": [{"auth": %q}]},
			"streamSettings": {"network": "hysteria", "security": "tls",
				"tlsSettings": {"alpn": ["h3"], "certificates": [{"certificate": %s, "key": %s}]},
				"hysteriaSettings": {"version": 2}}
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
	}`, serverPort, auth, pemLines(certificatePEM), pemLines(keyPEM)))

	pooled := hysteria.CleanPooledClients()
	for cycle := 1; cycle <= 3; cycle++ {
		clientPort := tcp.PickPort()
		stopClient := startJSONInstance(t, fmt.Sprintf(`{
			"log": {"loglevel": "warning"},
			"inbounds": [{
				"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
				"settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}
			}],
			"outbounds": [{
				"protocol": "hysteria",
				"settings": {"version": 2, "address": "127.0.0.1", "port": %d},
				"streamSettings": {"network": "hysteria", "security": "tls",
					"tlsSettings": {"alpn": ["h3"], "serverName": "localhost", "pinnedPeerCertSha256": "%x"},
					"hysteriaSettings": {"version": 2, "auth": %q}}
			}]
		}`, clientPort, echoDest.Port, serverPort, certificateHash, auth))

		payload := fmt.Sprintf("cycle %d", cycle)
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		echoed := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echoed); err != nil {
			t.Fatalf("cycle %d: no echo through the tunnel: %v", cycle, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if string(echoed) != payload {
			t.Fatalf("cycle %d: echo returned %q, want %q", cycle, echoed, payload)
		}

		stopClient()
		if remaining := hysteria.CleanPooledClients(); remaining != pooled {
			t.Fatalf("cycle %d: the pool holds %d clients after the instance stopped, want %d", cycle, remaining, pooled)
		}
	}
}

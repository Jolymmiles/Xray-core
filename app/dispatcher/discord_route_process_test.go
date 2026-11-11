//go:build integration

package dispatcher

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestDiscordRTCRouteProcessE2E is TestBitTorrentBlockProcessE2E for a routing
// rule protocol ["discordrtc"] -> block, on a real Xray process: the IP
// discovery request of Discord voice never reaches the destination, while
// DNS, a plain datagram, STUN and a plain TCP exchange through the same proxy
// are answered.
func TestDiscordRTCRouteProcessE2E(t *testing.T) {
	workDir := t.TempDir()
	xrayBin := btBuildXray(t, workDir)

	udpEcho := btNewUDPResponder(t)
	t.Cleanup(func() { _ = udpEcho.conn.Close() })
	tcpEcho := btNewTCPResponder(t)
	t.Cleanup(func() { _ = tcpEcho.listener.Close() })

	socksPort := btFreeTCPPort(t)
	config := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "socks",
			"settings": {"udp": true},
			"sniffing": {"enabled": true}
		}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "none"}}}
		],
		"routing": {"rules": [
			{"type": "field", "protocol": ["discordrtc"], "outboundTag": "block"}
		]}
	}`, socksPort)
	process := btStartXray(t, xrayBin, config, filepath.Join(workDir, "config.json"))
	btWaitSOCKS(t, process, socksPort)

	t.Run("dns query through proxy is answered", func(t *testing.T) {
		response := btRoundTripUDP(t, socksPort, udpEcho.addr, btDNSQuery(0xBEEF), 5*time.Second)
		if len(response) < 3 || response[2]&0x80 == 0 {
			t.Fatalf("unexpected DNS response: % x", response)
		}
	})

	t.Run("plain udp datagram through proxy is echoed", func(t *testing.T) {
		payload := []byte("plain-udp-control")
		if response := btRoundTripUDP(t, socksPort, udpEcho.addr, payload, 5*time.Second); !bytes.Equal(response, payload) {
			t.Fatalf("echo mismatch: got %q", response)
		}
	})

	t.Run("plain tcp exchange through proxy is echoed", func(t *testing.T) {
		payload := []byte("plain-tcp-control")
		if response := btRoundTripTCP(t, socksPort, tcpEcho.addr.Port, payload, 5*time.Second); !bytes.Equal(response, payload) {
			t.Fatalf("echo mismatch: got %q", response)
		}
	})

	t.Run("stun binding through proxy is echoed", func(t *testing.T) {
		payload := stunBinding()
		if response := btRoundTripUDP(t, socksPort, udpEcho.addr, payload, 5*time.Second); !bytes.Equal(response, payload) {
			t.Fatalf("echo mismatch: got % x", response)
		}
	})

	t.Run("discord ip discovery over udp is blocked", func(t *testing.T) {
		btAssertBlockedUDP(t, socksPort, udpEcho, discordIPDiscovery(), "Discord IP discovery")
	})
}

//go:build integration

package singmux_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// recordedDatagram is a datagram the destination or the client received: its
// size and its last byte, which tells the sender's datagrams apart.
type recordedDatagram struct {
	size int
	fill byte
}

func datagramSizes(datagrams []recordedDatagram) []int {
	out := make([]int, len(datagrams))
	for i, d := range datagrams {
		out[i] = d.size
	}
	return out
}

// startUDPDestination records each datagram it receives and echoes those of
// markerSize bytes. To "trigger" it replies with 9000 bytes, more than a
// socket read of Xray takes, then 7000 bytes and "pong".
func startUDPDestination(t *testing.T) (*net.UDPAddr, <-chan recordedDatagram) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	received := make(chan recordedDatagram, 64)
	go func() {
		packet := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(packet)
			if err != nil {
				return
			}
			received <- recordedDatagram{size: n, fill: packet[n-1]}
			switch {
			case string(packet[:n]) == "trigger":
				_, _ = conn.WriteToUDP(bytes.Repeat([]byte{0xB1}, 9000), from)
				_, _ = conn.WriteToUDP(bytes.Repeat([]byte{0xC1}, 7000), from)
				_, _ = conn.WriteToUDP([]byte("pong"), from)
			case n == markerSize:
				_, _ = conn.WriteToUDP(packet[:n], from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), received
}

// markerSize is the size of the datagrams that mark the end of a step: the
// destination echoes them, so their echo proves the session after the step.
const markerSize = 64

// receiveUntilMarker returns the datagrams the destination received before
// the marker that ends with fill.
func receiveUntilMarker(t *testing.T, received <-chan recordedDatagram, fill byte) []recordedDatagram {
	t.Helper()
	var got []recordedDatagram
	timeout := time.After(10 * time.Second)
	for {
		select {
		case d := <-received:
			if d.size == markerSize && d.fill == fill {
				return got
			}
			got = append(got, d)
		case <-timeout:
			t.Fatalf("the destination received %v but not the marker %#x", datagramSizes(got), fill)
		}
	}
}

// readUntil returns the datagrams conn receives before the one last reports,
// without the header bytes of each that the SOCKS relay adds.
func readUntil(t *testing.T, conn *net.UDPConn, header int, last func(recordedDatagram) bool) []recordedDatagram {
	t.Helper()
	var got []recordedDatagram
	packet := make([]byte, 65535)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := conn.ReadFromUDP(packet)
		if err != nil {
			t.Fatalf("the client received %v but not the last datagram: %v", datagramSizes(got), err)
		}
		if n <= header {
			t.Fatalf("a reply of %d bytes is shorter than its header", n)
		}
		d := recordedDatagram{size: n - header, fill: packet[n-1]}
		if last(d) {
			return got
		}
		got = append(got, d)
	}
}

func isMarker(fill byte) func(recordedDatagram) bool {
	return func(d recordedDatagram) bool { return d.size == markerSize && d.fill == fill }
}

func isPong(d recordedDatagram) bool { return d.size == 4 && d.fill == 'g' }

// TestLargeUDPDatagramProcessMatrix sends UDP datagrams above 8 KiB through
// one Xray server with real sing-box, Mihomo and Xray clients over each
// framing that carries them: VLESS, XUDP, Trojan, VMess with and without
// global padding and authenticated length. The server must pass each datagram
// it is handed on whole, drop a reply that its socket read cut at 8192 bytes
// rather than pass on its first 8192 bytes, and keep the session.
//
// The clients limit what reaches the server: sing-box and Mihomo read their
// SOCKS relay into buffers of 16 KiB (UDPBufferSize of sing), Mihomo's Trojan
// client splits a datagram above 8192 bytes into packets of 8192 bytes, and
// Xray's SOCKS relay reads 8192 bytes, so the Xray client drops a longer
// datagram.
func TestLargeUDPDatagramProcessMatrix(t *testing.T) {
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)

	for index, cell := range []struct {
		name, client, carrier, packetEncoding string
		padding                               bool
		// split is the size of the pieces into which the client splits a
		// large datagram, or 0; -1 if it drops one above 8192 bytes.
		split int
	}{
		{name: "sing-box/vless", client: "sing-box", carrier: "vless"},
		{name: "sing-box/vless-xudp", client: "sing-box", carrier: "vless", packetEncoding: "xudp"},
		{name: "sing-box/trojan", client: "sing-box", carrier: "trojan"},
		{name: "sing-box/vmess", client: "sing-box", carrier: "vmess"},
		{name: "sing-box/vmess-padding", client: "sing-box", carrier: "vmess", padding: true},
		// Mihomo's VLESS client always sends UDP as XUDP.
		{name: "mihomo/vless-xudp", client: "mihomo", carrier: "vless", packetEncoding: "xudp"},
		{name: "mihomo/trojan", client: "mihomo", carrier: "trojan", split: 8192},
		{name: "mihomo/vmess", client: "mihomo", carrier: "vmess"},
		{name: "mihomo/vmess-padding", client: "mihomo", carrier: "vmess", padding: true},
		{name: "xray/trojan", client: "xray", carrier: "trojan", split: -1},
	} {
		t.Run(cell.name, func(t *testing.T) {
			destination, received := startUDPDestination(t)
			serverPort := freeTCPPort(t)
			socksPort := freeTCPUDPPort(t)
			dir := t.TempDir()
			serverPath := filepath.Join(dir, "server.json")
			writeConfig(t, serverPath, largeDatagramServerConfig(t, cell.carrier, serverPort, certificate, privateKey))
			clientPath := filepath.Join(dir, "client.json")
			clientBinary, clientArgs := binaries.singBox, []string{"run", "-c", clientPath}
			var clientConfig []byte
			switch cell.client {
			case "sing-box":
				clientConfig = largeDatagramSingBoxConfig(t, cell.carrier, cell.packetEncoding, cell.padding, serverPort, socksPort)
			case "mihomo":
				clientPath = filepath.Join(dir, "client.yaml")
				clientConfig = largeDatagramMihomoConfig(cell.carrier, cell.padding, serverPort, socksPort)
				clientBinary, clientArgs = binaries.mihomo, []string{"-d", dir, "-f", clientPath}
			case "xray":
				clientConfig = largeDatagramXrayClientConfig(t, cell.carrier, serverPort, socksPort, certificate)
				clientBinary, clientArgs = binaries.xray, []string{"run", "-config", clientPath}
			}
			writeConfig(t, clientPath, clientConfig)
			server := startReadyE2EServer(t, binaries.xray, []string{"run", "-config", serverPath}, serverPort, "")
			client := startReadyE2EClient(t, cell.client, clientBinary, clientArgs, socksPort)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("server logs:\n%s", server.logs.String())
					t.Logf("client logs:\n%s", client.logs.String())
				}
			})

			control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			if err := control.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := socksGreeting(control); err != nil {
				t.Fatal(err)
			}
			if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			relay, err := readSOCKSReplyAddress(control)
			if err != nil {
				t.Fatal(err)
			}
			if relay.IP.IsUnspecified() {
				relay.IP = net.IPv4(127, 0, 0, 1)
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			send := func(payload []byte) {
				t.Helper()
				packet := append([]byte{0, 0, 0, 1}, destination.IP.To4()...)
				packet = binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
				if _, err := udp.WriteToUDP(append(packet, payload...), relay); err != nil {
					t.Fatal(err)
				}
			}
			// mark ends a step: the destination receives the marker after
			// what the step sent, and its echo proves the session.
			mark := func(fill byte) []recordedDatagram {
				t.Helper()
				send(bytes.Repeat([]byte{fill}, markerSize))
				got := receiveUntilMarker(t, received, fill)
				if echoes := readUntil(t, udp, 10, isMarker(fill)); len(echoes) != 0 {
					t.Fatalf("the client received %v before the echo of the marker", datagramSizes(echoes))
				}
				return got
			}

			// The whole path first.
			base := byte(0x10 + 4*index)
			if got := mark(base); len(got) != 0 {
				t.Fatalf("the destination received %v before the first marker", datagramSizes(got))
			}
			for step, size := range []int{9000, 14000, 65000} {
				fill := byte(0x80 + 4*index + step)
				send(bytes.Repeat([]byte{fill}, size))
				got := mark(base + 1 + byte(step))
				t.Logf("the destination received datagrams of %v bytes for %d", datagramSizes(got), size)
				for _, d := range got {
					if d.fill != fill {
						t.Errorf("the destination received a datagram ending with %#x, want %#x", d.fill, fill)
					}
				}
				var want []int
				switch {
				case cell.split < 0:
					// the Xray client drops it
				case size > 16*1024:
					// sing-box and Mihomo cut it; record what arrives
					continue
				case cell.split > 0:
					for rest := size; rest > 0; rest -= cell.split {
						want = append(want, min(rest, cell.split))
					}
				default:
					want = []int{size}
				}
				if !slices.Equal(datagramSizes(got), want) {
					t.Errorf("the destination received %v for %d bytes, want %v", datagramSizes(got), size, want)
				}
			}

			// The server reads a reply of 9000 bytes into 8192 and drops it;
			// the replies after it arrive.
			send([]byte("trigger"))
			replies := readUntil(t, udp, 10, isPong)
			if !slices.Equal(datagramSizes(replies), []int{7000}) || replies[0].fill != 0xC1 {
				t.Errorf("the client received replies of %v bytes before pong, want [7000]", datagramSizes(replies))
			}
		})
	}
}

// TestDokodemoTruncatedDatagramProcess sends a datagram above the 8192 bytes
// that the UDP hub reads through a dokodemo-door inbound, and asks for a reply
// above the 8192 bytes freedom reads. Neither may arrive cut.
func TestDokodemoTruncatedDatagramProcess(t *testing.T) {
	binaries := buildE2EBinaries(t, t.TempDir())
	destination, received := startUDPDestination(t)
	port := freeTCPUDPPort(t)
	serverConfig, err := json.MarshalIndent(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": destination.Port, "network": "tcp,udp"},
		}},
		"outbounds": []any{largeDatagramFreedom()},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(t.TempDir(), "server.json")
	writeConfig(t, serverPath, serverConfig)
	server := startReadyE2EServer(t, binaries.xray, []string{"run", "-config", serverPath}, port, "")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
		}
	})
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mark := func(fill byte) []recordedDatagram {
		t.Helper()
		if _, err := client.Write(bytes.Repeat([]byte{fill}, markerSize)); err != nil {
			t.Fatal(err)
		}
		got := receiveUntilMarker(t, received, fill)
		if echoes := readUntil(t, client, 0, isMarker(fill)); len(echoes) != 0 {
			t.Fatalf("the client received %v before the echo of the marker", datagramSizes(echoes))
		}
		return got
	}

	if got := mark(0x11); len(got) != 0 {
		t.Fatalf("the destination received %v before the first marker", datagramSizes(got))
	}
	if _, err := client.Write(bytes.Repeat([]byte{0xA1}, 9000)); err != nil {
		t.Fatal(err)
	}
	if got := mark(0x12); len(got) != 0 {
		t.Errorf("the destination received datagrams of %v bytes, want the datagram of 9000 dropped", datagramSizes(got))
	}
	if _, err := client.Write([]byte("trigger")); err != nil {
		t.Fatal(err)
	}
	if replies := readUntil(t, client, 0, isPong); !slices.Equal(datagramSizes(replies), []int{7000}) {
		t.Errorf("the client received replies of %v bytes before pong, want [7000]", datagramSizes(replies))
	}
}

func largeDatagramFreedom() map[string]any {
	// the destination is on loopback, which freedom blocks by default
	return map[string]any{
		"protocol": "freedom",
		"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
	}
}

func largeDatagramServerConfig(t *testing.T, carrier string, port int, certificate, privateKey string) []byte {
	t.Helper()
	settings := map[string]any{"clients": []any{map[string]any{"id": testUUID}}}
	switch carrier {
	case "vless":
		settings["decryption"] = "none"
	case "trojan":
		settings = map[string]any{"clients": []any{map[string]any{"password": testPassword}}}
	}
	inbound := map[string]any{"listen": "127.0.0.1", "port": port, "protocol": carrier, "settings": settings}
	if carrier == "trojan" {
		inbound["streamSettings"] = xrayTLSSettings(true, certificate, privateKey)
	}
	config, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": []any{largeDatagramFreedom()},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func largeDatagramSingBoxConfig(t *testing.T, carrier, packetEncoding string, padding bool, serverPort, socksPort int) []byte {
	t.Helper()
	outbound := map[string]any{"type": carrier, "server": "127.0.0.1", "server_port": serverPort}
	switch carrier {
	case "vless":
		outbound["uuid"] = testUUID
		outbound["packet_encoding"] = packetEncoding
	case "trojan":
		outbound["password"] = testPassword
		outbound["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}
	case "vmess":
		outbound["uuid"] = testUUID
		outbound["security"] = "aes-128-gcm"
		outbound["global_padding"] = padding
		outbound["authenticated_length"] = padding
	}
	config, err := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{outbound},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func largeDatagramMihomoConfig(carrier string, padding bool, serverPort, socksPort int) []byte {
	settings := fmt.Sprintf("    uuid: %s\n    udp: true\n    tls: false\n", testUUID)
	switch carrier {
	case "trojan":
		settings = fmt.Sprintf("    password: %s\n    udp: true\n    tls: true\n    sni: localhost\n    skip-cert-verify: true\n", testPassword)
	case "vmess":
		settings += "    cipher: aes-128-gcm\n    alterId: 0\n"
		if padding {
			settings += "    global-padding: true\n    authenticated-length: true\n"
		}
	}
	return []byte(fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: warning\nproxies:\n  - name: e2e-peer\n    type: %s\n    server: 127.0.0.1\n    port: %d\n%sproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - e2e-peer\n", socksPort, carrier, serverPort, settings))
}

func largeDatagramXrayClientConfig(t *testing.T, carrier string, serverPort, socksPort int, certificate string) []byte {
	t.Helper()
	if carrier != "trojan" {
		t.Fatalf("no Xray client config for %s", carrier)
	}
	config, err := json.MarshalIndent(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort, "password": testPassword,
			}}},
			"streamSettings": xrayTLSSettings(false, certificate, ""),
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

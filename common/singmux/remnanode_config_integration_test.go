//go:build integration

package singmux_test

import (
	"bytes"
	cryptotls "crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/infra/conf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	deploymentServerUUID = "b831381d-6324-0000-ad4f-8cda48b30811"
	deploymentRouteUUID  = "b831381d-6324-0032-ad4f-8cda48b30811"
	deploymentMobileUUID = "728f97df-f5d2-0000-a422-15e62d0dcfd6"
)

type deploymentDNSUpstream struct {
	address any
	queries atomic.Uint64
}

type deploymentDNSSet struct {
	servers []*deploymentDNSUpstream
	close   func()
}

func TestRemnaNodeConfigProcessE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("full RemnaNode deployment configuration process test")
	}

	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, certificateKey := generateCertificate(t, workDir)
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", filepath.Join(xrayRoot, "resources"))

	deploymentIPv6 := deploymentIPv6Address(t)
	dnsSet := startDeploymentDNS(t, deploymentIPv6)
	httpPort := startDeploymentHTTPServers(t, deploymentIPv6)
	tlsPort := startDeploymentTLSServers(t, certificate, certificateKey, deploymentIPv6)
	realityTarget, proxyV2Count := startDeploymentRealityTarget(t, certificate, certificateKey)

	muxPort := freeTCPPort(t)
	directPort := freeTCPPort(t)
	accessPath := filepath.Join(workDir, "access.log")
	errorPath := filepath.Join(workDir, "error.log")
	serverPath := filepath.Join(workDir, "server.json")
	writeConfig(t, serverPath, remnaNodeServerConfig(t, muxPort, directPort, accessPath, errorPath, realityTarget, dnsSet))
	server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
	waitTCP(t, server, muxPort)
	waitTCP(t, server, directPort)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server logs:\n%s", server.logs.String())
			if content, err := os.ReadFile(accessPath); err == nil {
				t.Logf("access log:\n%s", content)
			}
			if content, err := os.ReadFile(errorPath); err == nil {
				t.Logf("error log:\n%s", content)
			}
		}
	})

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, mode := range []string{"direct", "smux"} {
			t.Run(peer+"/"+mode, func(t *testing.T) {
				useSMUX := mode == "smux"
				serverPort := directPort
				inboundTag := "reality-pro-de"
				if useSMUX {
					serverPort = muxPort
					inboundTag = "reality-pro-de-mux"
				}
				socksPort := freeTCPPort(t)
				clientBinary, clientArgs, clientConfig := remnaNodeClientConfig(t, binaries, peer, serverPort, socksPort, deploymentRouteUUID, useSMUX)
				clientPath := filepath.Join(t.TempDir(), "client"+configExtension(peer, peer == "xray"))
				clientArgs = replaceConfigPath(clientArgs, clientPath)
				writeConfig(t, clientPath, clientConfig)
				client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)
				response := waitDeploymentHTTPForwarding(t, client, socksPort, httpPort, "www.google.com")
				if !strings.Contains(response, "family=ipv4") {
					t.Fatalf("DIRECT did not use ForceIPv4: %q", response)
				}
				waitLegacyAccessRoute(t, accessPath, inboundTag, "DIRECT")
			})
		}
	}

	if proxyV2Count.Load() == 0 {
		t.Fatal("REALITY Unix target did not receive a PROXY protocol v2 header")
	}

	t.Run("routing-and-dns", func(t *testing.T) {
		socksPort := freeTCPPort(t)
		clientPath := filepath.Join(t.TempDir(), "client.json")
		writeConfig(t, clientPath, remnaNodeXrayClientConfig(t, directPort, socksPort, deploymentServerUUID, false))
		client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
		waitSOCKS(t, client, socksPort)

		t.Run("http-sniff-routes-youtube-to-ipv6-interface", func(t *testing.T) {
			response := runSOCKSHTTP(t, socksPort, httpPort, "www.youtube.com")
			if !strings.Contains(response, "family=ipv6") {
				t.Fatalf("YT did not use ForceIPv6: %q", response)
			}
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "YT")
		})

		t.Run("tls-sniff-routes-google-to-ipv6-interface", func(t *testing.T) {
			response := runSOCKSTLSHTTP(t, socksPort, tlsPort, "www.google.com")
			if !strings.Contains(response, "family=ipv6") {
				t.Fatalf("TLS-sniffed YT route did not use ForceIPv6: %q", response)
			}
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "YT")
		})

		t.Run("dns-out-fallback-cache-and-query-strategy", func(t *testing.T) {
			response := runSOCKSDNSQuery(t, socksPort, "cache.remnanode.test.", mdns.TypeA)
			assertDNSAnswer(t, response, "127.0.0.1")
			for index, upstream := range dnsSet.servers {
				if upstream.queries.Load() == 0 {
					t.Fatalf("DNS fallback did not reach upstream %d (%v)", index, upstream.address)
				}
			}
			before := dnsQueryCounts(dnsSet)
			response = runSOCKSDNSQuery(t, socksPort, "cache.remnanode.test.", mdns.TypeA)
			assertDNSAnswer(t, response, "127.0.0.1")
			if after := dnsQueryCounts(dnsSet); after[len(after)-1] != before[len(before)-1] {
				t.Fatalf("disableCache=false did not cache the successful upstream response: before=%v after=%v", before, after)
			}
			response = runSOCKSDNSQuery(t, socksPort, "cache6.remnanode.test.", mdns.TypeAAAA)
			assertDNSAnswer(t, response, deploymentIPv6)
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "dns-out")
		})

		t.Run("udp-443-is-blocked", func(t *testing.T) {
			expectSOCKSUDPTimeout(t, socksPort, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, []byte("blocked-quic"))
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "BLOCK")
		})

		t.Run("geoip-private-is-blocked", func(t *testing.T) {
			expectSOCKSTCPFailure(t, socksPort, "127.0.0.1", httpPort, []byte("not-http"))
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "BLOCK")
		})

		t.Run("tcp-25-is-blocked", func(t *testing.T) {
			expectSOCKSTCPFailure(t, socksPort, "192.0.2.1", 25, []byte("smtp"))
			waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "BLOCK")
		})
	})

	t.Run("mobile-user-is-blocked", func(t *testing.T) {
		socksPort := freeTCPPort(t)
		clientPath := filepath.Join(t.TempDir(), "mobile.json")
		writeConfig(t, clientPath, remnaNodeXrayClientConfig(t, directPort, socksPort, deploymentMobileUUID, false))
		client := startE2EProcess(t, binaries.xray, "run", "-config", clientPath)
		waitSOCKS(t, client, socksPort)
		expectSOCKSTCPFailure(t, socksPort, "192.0.2.1", httpPort, []byte("mobile"))
		waitLegacyAccessRoute(t, accessPath, "reality-pro-de", "BLOCK")
	})

	if _, err := os.Stat(accessPath); err != nil {
		t.Fatalf("legacy access log was not created: %v", err)
	}
	if _, err := os.Stat(errorPath); err != nil {
		t.Fatalf("legacy error log was not created: %v", err)
	}
}

func remnaNodeServerConfig(t *testing.T, muxPort, directPort int, accessPath, errorPath, realityTarget string, dnsSet *deploymentDNSSet) []byte {
	t.Helper()
	clients := []any{
		map[string]any{"id": deploymentServerUUID, "email": "regular-user"},
		map[string]any{"id": deploymentMobileUUID, "email": "Mobile_user"},
	}
	inbound := func(tag string, port int) map[string]any {
		return map[string]any{
			"tag": tag, "port": strconv.Itoa(port), "listen": "127.0.0.1", "protocol": "vless",
			"settings": map[string]any{"flow": "", "clients": clients, "decryption": "none"},
			"sniffing": map[string]any{"enabled": true, "routeOnly": false, "destOverride": []string{"http", "tls"}},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"show": false, "xver": 2, "target": realityTarget, "shortIds": []string{""},
					"privateKey": realityPrivateKey, "serverNames": []string{"localhost"},
				},
			},
		}
	}
	dnsServers := make([]any, 0, len(dnsSet.servers))
	for _, server := range dnsSet.servers {
		dnsServers = append(dnsServers, server.address)
	}
	config := map[string]any{
		"log": map[string]any{"error": errorPath, "access": accessPath, "loglevel": "warning"},
		"dns": map[string]any{
			"tag": "dns_inbound", "servers": dnsServers, "disableCache": false,
			"queryStrategy": "UseIP", "disableFallback": false,
		},
		"inbounds": []any{inbound("reality-pro-de-mux", muxPort), inbound("reality-pro-de", directPort)},
		"outbounds": []any{
			map[string]any{"tag": "DIRECT", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "ForceIPv4", "finalRules": []any{map[string]any{"action": "allow"}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"tcpFastOpen": true}}},
			map[string]any{"tag": "YT", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "ForceIPv6", "finalRules": []any{map[string]any{"action": "allow"}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"interface": deploymentLoopbackInterface(t), "tcpFastOpen": true}}},
			map[string]any{"tag": "TORRENT", "protocol": "blackhole"},
			map[string]any{"tag": "BLOCK", "protocol": "blackhole"},
			map[string]any{"tag": "dns-out", "protocol": "dns"},
		},
		"routing": map[string]any{
			"rules": []any{
				map[string]any{"port": "53", "network": "udp", "outboundTag": "dns-out"},
				map[string]any{"port": "443", "network": "udp", "outboundTag": "BLOCK"},
				map[string]any{"user": []string{"Mobile_user"}, "outboundTag": "BLOCK"},
				map[string]any{"domain": []string{"geosite:youtube", "full:www.google.com"}, "vlessRoute": "50", "outboundTag": "DIRECT"},
				map[string]any{"ip": []string{"geoip:private"}, "outboundTag": "BLOCK"},
				map[string]any{"port": "25", "network": "tcp", "outboundTag": "BLOCK"},
				map[string]any{"domain": []string{"geosite:youtube", "full:www.google.com"}, "outboundTag": "YT"},
			},
			"domainStrategy": "IPIfNonMatch",
		},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func remnaNodeClientConfig(t *testing.T, binaries e2eBinaries, peer string, serverPort, socksPort int, id string, smux bool) (string, []string, []byte) {
	t.Helper()
	switch peer {
	case "xray":
		return binaries.xray, []string{"run", "-config", "client.json"}, remnaNodeXrayClientConfig(t, serverPort, socksPort, id, smux)
	case "sing-box":
		outbound := map[string]any{
			"type": "vless", "server": "127.0.0.1", "server_port": serverPort, "uuid": id,
			"tls": map[string]any{
				"enabled": true, "server_name": "localhost",
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": realityPublicKey, "short_id": ""},
			},
		}
		if smux {
			outbound["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_connections": 1, "padding": true}
		}
		config := map[string]any{
			"log":       map[string]any{"level": "warn"},
			"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{outbound},
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return binaries.singBox, []string{"run", "-c", "client.json"}, encoded
	case "mihomo":
		smuxLines := ""
		if smux {
			smuxLines = "    smux:\n      enabled: true\n      protocol: smux\n      max-connections: 1\n      padding: true\n"
		}
		config := fmt.Sprintf("socks-port: %d\nallow-lan: false\nmode: global\nlog-level: warning\nproxies:\n  - name: deployment\n    type: vless\n    server: 127.0.0.1\n    port: %d\n    uuid: %s\n    network: tcp\n    tls: true\n    servername: localhost\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %s\n      short-id: ''\n%sproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n      - deployment\n", socksPort, serverPort, id, realityPublicKey, smuxLines)
		return binaries.mihomo, []string{"-d", ".", "-f", "client.yaml"}, []byte(config)
	default:
		t.Fatalf("unsupported peer %q", peer)
		return "", nil, nil
	}
}

func remnaNodeXrayClientConfig(t *testing.T, serverPort, socksPort int, id string, smux bool) []byte {
	t.Helper()
	outbound := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort,
			"users": []any{map[string]any{"id": id, "encryption": "none", "flow": ""}},
		}}},
		"streamSettings": map[string]any{
			"network": "raw", "security": "reality",
			"realitySettings": map[string]any{
				"show": false, "fingerprint": "chrome", "serverName": "localhost",
				"publicKey": realityPublicKey, "shortId": "", "spiderX": "/",
			},
		},
	}
	if smux {
		outbound["smux"] = map[string]any{"enabled": true, "protocol": "smux", "maxConnections": 1, "padding": true}
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		}},
		"outbounds": []any{outbound},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func deploymentLoopbackInterface(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("XRAY_E2E_YT_INTERFACE"); configured != "" {
		if _, err := net.InterfaceByName(configured); err != nil {
			t.Fatalf("XRAY_E2E_YT_INTERFACE=%q: %v", configured, err)
		}
		return configured
	}
	name := "lo"
	if runtime.GOOS == "darwin" {
		name = "lo0"
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("loopback interface %q: %v", name, err)
	}
	return name
}

func deploymentIPv6Address(t *testing.T) string {
	t.Helper()
	configured := os.Getenv("XRAY_E2E_YT_IPV6")
	if configured == "" {
		return "::1"
	}
	parsed := net.ParseIP(configured)
	if parsed == nil || parsed.To4() != nil {
		t.Fatalf("XRAY_E2E_YT_IPV6=%q is not an IPv6 address", configured)
	}
	interfaceName := os.Getenv("XRAY_E2E_YT_INTERFACE")
	if interfaceName == "" {
		t.Fatal("XRAY_E2E_YT_IPV6 requires XRAY_E2E_YT_INTERFACE")
	}
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		t.Fatalf("XRAY_E2E_YT_INTERFACE=%q: %v", interfaceName, err)
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		t.Fatalf("addresses for XRAY_E2E_YT_INTERFACE=%q: %v", interfaceName, err)
	}
	for _, address := range addresses {
		ip, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil && ip.Equal(parsed) {
			return parsed.String()
		}
	}
	t.Fatalf("XRAY_E2E_YT_IPV6=%q is not assigned to interface %q", configured, interfaceName)
	return ""
}

func startDeploymentDNS(t *testing.T, ipv6Address string) *deploymentDNSSet {
	t.Helper()
	set := &deploymentDNSSet{}
	var closers []func()

	for range 2 {
		upstream := &deploymentDNSUpstream{}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			upstream.queries.Add(1)
			http.Error(writer, "fallback", http.StatusServiceUnavailable)
		})
		server := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})}
		go func() { _ = server.Serve(listener) }()
		closers = append(closers, func() { _ = server.Close() })
		upstream.address = "h2c+local://127.0.0.1:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) + "/dns-query"
		set.servers = append(set.servers, upstream)
	}

	for index := range 2 {
		upstream := &deploymentDNSUpstream{}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		handler := mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
			upstream.queries.Add(1)
			response := new(mdns.Msg)
			response.SetReply(request)
			if index == 0 {
				response.Rcode = mdns.RcodeServerFailure
			} else {
				appendDeploymentDNSAnswers(response, ipv6Address)
			}
			if err := writer.WriteMsg(response); err != nil {
				t.Logf("deployment DNS TCP upstream %d write: %v", index, err)
			}
		})
		server := &mdns.Server{Listener: listener, Handler: handler}
		go func() { _ = server.ActivateAndServe() }()
		closers = append(closers, func() { _ = server.Shutdown() })
		upstream.address = "tcp+local://127.0.0.1:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
		set.servers = append(set.servers, upstream)
	}

	set.close = func() {
		for _, closeServer := range closers {
			closeServer()
		}
	}
	t.Cleanup(set.close)
	return set
}

func appendDeploymentDNSAnswers(message *mdns.Msg, ipv6Address string) {
	for _, question := range message.Question {
		switch question.Qtype {
		case mdns.TypeA:
			record, _ := mdns.NewRR(question.Name + " 60 IN A 127.0.0.1")
			message.Answer = append(message.Answer, record)
		case mdns.TypeAAAA:
			record, _ := mdns.NewRR(question.Name + " 60 IN AAAA " + ipv6Address)
			message.Answer = append(message.Answer, record)
		}
	}
}

func deploymentTLSConfig(t *testing.T, certificate, privateKey string) *cryptotls.Config {
	t.Helper()
	pair, err := cryptotls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &cryptotls.Config{Certificates: []cryptotls.Certificate{pair}, MinVersion: cryptotls.VersionTLS12}
}

func startDeploymentHTTPServers(t *testing.T, ipv6Address string) int {
	t.Helper()
	listener4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener4.Addr().(*net.TCPAddr).Port
	listener6, err := net.Listen("tcp6", net.JoinHostPort(ipv6Address, strconv.Itoa(port)))
	if err != nil {
		listener4.Close()
		t.Skipf("IPv6 loopback is required for ForceIPv6 E2E: %v", err)
	}
	serveDeploymentHTTP(t, listener4, "ipv4")
	serveDeploymentHTTP(t, listener6, "ipv6")
	return port
}

func startDeploymentTLSServers(t *testing.T, certificate, privateKey, ipv6Address string) int {
	t.Helper()
	listener4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener4.Addr().(*net.TCPAddr).Port
	listener6, err := net.Listen("tcp6", net.JoinHostPort(ipv6Address, strconv.Itoa(port)))
	if err != nil {
		listener4.Close()
		t.Skipf("IPv6 loopback is required for ForceIPv6 E2E: %v", err)
	}
	serveDeploymentHTTP(t, cryptotls.NewListener(listener4, deploymentTLSConfig(t, certificate, privateKey)), "ipv4")
	serveDeploymentHTTP(t, cryptotls.NewListener(listener6, deploymentTLSConfig(t, certificate, privateKey)), "ipv6")
	return port
}

func serveDeploymentHTTP(t *testing.T, listener net.Listener, family string) {
	t.Helper()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "family="+family)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

func startDeploymentRealityTarget(t *testing.T, certificate, privateKey string) (string, *atomic.Uint64) {
	t.Helper()
	socketDir, err := os.MkdirTemp("/tmp", "xr-reality-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	path := filepath.Join(socketDir, "nginx.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	counter := new(atomic.Uint64)
	tlsConfig := deploymentTLSConfig(t, certificate, privateKey)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				if readProxyV2Header(connection) != nil {
					return
				}
				counter.Add(1)
				tlsConnection := cryptotls.Server(connection, tlsConfig)
				_ = tlsConnection.SetDeadline(time.Now().Add(10 * time.Second))
				_ = tlsConnection.Handshake()
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return path, counter
}

func readProxyV2Header(reader io.Reader) error {
	header := make([]byte, 16)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	signature := []byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}
	if !bytes.Equal(header[:12], signature) || header[12]>>4 != 2 {
		return fmt.Errorf("invalid PROXY v2 header")
	}
	payloadLength := int(binary.BigEndian.Uint16(header[14:16]))
	if payloadLength > 0 {
		_, err := io.CopyN(io.Discard, reader, int64(payloadLength))
		return err
	}
	return nil
}

func runSOCKSHTTP(t *testing.T, socksPort, destinationPort int, host string) string {
	t.Helper()
	response, err := runSOCKSHTTPAttempt(socksPort, destinationPort, host)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func waitDeploymentHTTPForwarding(t *testing.T, process *e2eProcess, socksPort, destinationPort int, host string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := runSOCKSHTTPAttempt(socksPort, destinationPort, host)
		if err == nil && strings.Contains(response, "family=ipv4") {
			return response
		}
		if err == nil {
			err = fmt.Errorf("unexpected HTTP response %q", response)
		}
		lastErr = err
		select {
		case processErr := <-process.done:
			t.Fatalf("client exited before HTTP forwarding became ready: %v\n%s", processErr, process.logs.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("HTTP forwarding did not become ready: %v\n%s", lastErr, process.logs.String())
	return ""
}

func runSOCKSHTTPAttempt(socksPort, destinationPort int, host string) (string, error) {
	connection, err := dialSOCKSTCPAttempt(socksPort, "192.0.2.1", destinationPort)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return "", err
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		return "", err
	}
	if len(response) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	return string(response), nil
}

func runSOCKSTLSHTTP(t *testing.T, socksPort, destinationPort int, host string) string {
	t.Helper()
	connection := dialSOCKSTCP(t, socksPort, "192.0.2.1", destinationPort)
	tlsConnection := cryptotls.Client(connection, &cryptotls.Config{ServerName: host, InsecureSkipVerify: true}) // #nosec G402 -- isolated test certificate
	defer tlsConnection.Close()
	_ = tlsConnection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConnection.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(tlsConnection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response, err := io.ReadAll(tlsConnection)
	if err != nil {
		t.Fatal(err)
	}
	return string(response)
}

func dialSOCKSTCP(t *testing.T, socksPort int, host string, port int) net.Conn {
	t.Helper()
	connection, err := dialSOCKSTCPAttempt(socksPort, host, port)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func dialSOCKSTCPAttempt(socksPort int, host string, port int) (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := socksGreeting(connection); err != nil {
		connection.Close()
		return nil, err
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		request = append(request, 1)
		request = append(request, ip...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			connection.Close()
			return nil, fmt.Errorf("SOCKS destination domain length %d is outside 1..255", len(host))
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := connection.Write(request); err != nil {
		connection.Close()
		return nil, err
	}
	if err := readSOCKSReply(connection); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func runSOCKSDNSQuery(t *testing.T, socksPort int, domain string, queryType uint16) *mdns.Msg {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(domain, queryType)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	response := exchangeSOCKSUDP(t, socksPort, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}, payload, true)
	message := new(mdns.Msg)
	if err := message.Unpack(response); err != nil {
		t.Fatal(err)
	}
	return message
}

func assertDNSAnswer(t *testing.T, message *mdns.Msg, expected string) {
	t.Helper()
	for _, answer := range message.Answer {
		switch record := answer.(type) {
		case *mdns.A:
			if record.A.String() == expected {
				return
			}
		case *mdns.AAAA:
			if record.AAAA.String() == expected {
				return
			}
		}
	}
	t.Fatalf("DNS response does not contain %s: %v", expected, message.Answer)
}

func expectSOCKSUDPTimeout(t *testing.T, socksPort int, destination *net.UDPAddr, payload []byte) {
	t.Helper()
	if response := exchangeSOCKSUDP(t, socksPort, destination, payload, false); response != nil {
		t.Fatalf("blocked UDP request returned %x", response)
	}
}

func exchangeSOCKSUDP(t *testing.T, socksPort int, destination *net.UDPAddr, payload []byte, expectResponse bool) []byte {
	t.Helper()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socksGreeting(control); err != nil {
		t.Fatal(err)
	}
	_, _ = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
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
	deadline := 5 * time.Second
	if !expectResponse {
		deadline = 750 * time.Millisecond
	}
	_ = udp.SetDeadline(time.Now().Add(deadline))
	packet := append([]byte{0, 0, 0, 1}, destination.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
	packet = append(packet, payload...)
	if _, err := udp.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, _, err := udp.ReadFromUDP(buffer)
	if err != nil {
		if !expectResponse {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil
			}
		}
		t.Fatal(err)
	}
	offset, err := socksAddressLength(buffer[:n], 3)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[offset:n]...)
}

func expectSOCKSTCPFailure(t *testing.T, socksPort int, host string, port int, payload []byte) {
	t.Helper()
	connection := dialSOCKSTCP(t, socksPort, host, port)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(750 * time.Millisecond))
	if _, err := connection.Write(payload); err != nil {
		return
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, buffer); err == nil && bytes.Equal(buffer, payload) {
		t.Fatal("blocked TCP request completed an echo round trip")
	}
}

func waitLegacyAccessRoute(t *testing.T, path, inbound, outbound string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	marker := "[" + inbound + " -> " + outbound + "]"
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(path)
		if err == nil && bytes.Contains(content, []byte(marker)) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	content, _ := os.ReadFile(path)
	t.Fatalf("access log does not contain %q:\n%s", marker, content)
}

func dnsQueryCounts(set *deploymentDNSSet) []uint64 {
	counts := make([]uint64, len(set.servers))
	for index, server := range set.servers {
		counts[index] = server.queries.Load()
	}
	return counts
}

func TestRemnaNodeProductionConfigContract(t *testing.T) {
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", filepath.Join(xrayRoot, "resources"))

	var config conf.Config
	if err := json.Unmarshal(remnaNodeProductionConfig(), &config); err != nil {
		t.Fatal(err)
	}

	if config.LogConfig == nil || config.LogConfig.ErrorLog != "/var/log/remnanode/error.log" ||
		config.LogConfig.AccessLog != "/var/log/remnanode/access.log" || config.LogConfig.LogLevel != "warning" {
		t.Fatalf("log contract changed: %#v", config.LogConfig)
	}
	if config.DNSConfig == nil || config.DNSConfig.Tag != "dns_inbound" ||
		config.DNSConfig.QueryStrategy != "UseIP" || config.DNSConfig.DisableCache || config.DNSConfig.DisableFallback {
		t.Fatalf("DNS policy contract changed: %#v", config.DNSConfig)
	}
	wantDNS := []string{
		"https+local://1.1.1.1/dns-query",
		"https+local://dns.google/dns-query",
		"1.1.1.1",
		"8.8.8.8",
	}
	if len(config.DNSConfig.Servers) != len(wantDNS) {
		t.Fatalf("DNS server count = %d, want %d", len(config.DNSConfig.Servers), len(wantDNS))
	}
	for index, want := range wantDNS {
		if got := config.DNSConfig.Servers[index].Address.String(); got != want {
			t.Fatalf("DNS server %d = %q, want %q", index, got, want)
		}
	}

	wantInboundTags := []string{"reality-pro-de-mux", "reality-pro-de"}
	wantInboundPorts := []string{"443", "8443"}
	if len(config.InboundConfigs) != len(wantInboundTags) {
		t.Fatalf("inbound count = %d, want %d", len(config.InboundConfigs), len(wantInboundTags))
	}
	for index := range config.InboundConfigs {
		inbound := &config.InboundConfigs[index]
		if inbound.Tag != wantInboundTags[index] || inbound.Protocol != "vless" || inbound.ListenOn.String() != "0.0.0.0" ||
			inbound.PortList.String() != wantInboundPorts[index] {
			t.Fatalf("inbound %d contract changed: tag=%q protocol=%q listen=%v port=%v", index, inbound.Tag, inbound.Protocol, inbound.ListenOn, inbound.PortList)
		}
		var vlessSettings conf.VLessInboundConfig
		if err := json.Unmarshal(*inbound.Settings, &vlessSettings); err != nil {
			t.Fatal(err)
		}
		if vlessSettings.Flow != "" || vlessSettings.Decryption != "none" || vlessSettings.Clients == nil || len(vlessSettings.Clients) != 0 {
			t.Fatalf("inbound %d VLESS settings changed: %#v", index, vlessSettings)
		}
		if inbound.SniffingConfig == nil || !inbound.SniffingConfig.Enabled || inbound.SniffingConfig.RouteOnly ||
			strings.Join(inbound.SniffingConfig.DestOverride, ",") != "http,tls" {
			t.Fatalf("inbound %d sniffing contract changed: %#v", index, inbound.SniffingConfig)
		}
		stream := inbound.StreamSetting
		if stream == nil || stream.Network == nil || string(*stream.Network) != "raw" || stream.Security != "reality" || stream.REALITYSettings == nil {
			t.Fatalf("inbound %d stream contract changed: %#v", index, stream)
		}
		reality := stream.REALITYSettings
		var target string
		if err := json.Unmarshal(reality.Target, &target); err != nil {
			t.Fatal(err)
		}
		if reality.Show || reality.Xver != 2 || target != "/dev/shm/nginx.sock" ||
			len(reality.ShortIds) != 1 || reality.ShortIds[0] != "" ||
			len(reality.ServerNames) != 1 || reality.ServerNames[0] != "pro-de.emrata.top" ||
			reality.PrivateKey != realityPrivateKey {
			t.Fatalf("inbound %d REALITY contract changed: %#v", index, reality)
		}
	}

	wantOutboundTags := []string{"DIRECT", "YT", "TORRENT", "BLOCK", "dns-out"}
	if len(config.OutboundConfigs) != len(wantOutboundTags) {
		t.Fatalf("outbound count = %d, want %d", len(config.OutboundConfigs), len(wantOutboundTags))
	}
	for index, want := range wantOutboundTags {
		if got := config.OutboundConfigs[index].Tag; got != want {
			t.Fatalf("outbound %d tag = %q, want %q", index, got, want)
		}
	}
	assertFreedomContract(t, &config.OutboundConfigs[0], "ForceIPv4", "")
	assertFreedomContract(t, &config.OutboundConfigs[1], "ForceIPv6", "yt")
	if config.OutboundConfigs[2].Protocol != "blackhole" || config.OutboundConfigs[3].Protocol != "blackhole" ||
		config.OutboundConfigs[4].Protocol != "dns" {
		t.Fatalf("non-freedom outbound protocols changed: %q, %q, %q", config.OutboundConfigs[2].Protocol, config.OutboundConfigs[3].Protocol, config.OutboundConfigs[4].Protocol)
	}

	if config.RouterConfig == nil || config.RouterConfig.DomainStrategy == nil || *config.RouterConfig.DomainStrategy != "IPIfNonMatch" ||
		len(config.RouterConfig.RuleList) != 7 {
		t.Fatalf("routing contract changed: %#v", config.RouterConfig)
	}
	wantRules := []string{
		`{"port":"53","network":"udp","outboundTag":"dns-out"}`,
		`{"port":"443","network":"udp","outboundTag":"BLOCK"}`,
		`{"user":["Mobile_user"],"outboundTag":"BLOCK"}`,
		`{"domain":["geosite:youtube","full:www.google.com"],"vlessRoute":"50","outboundTag":"DIRECT"}`,
		`{"ip":["geoip:private"],"outboundTag":"BLOCK"}`,
		`{"port":"25","network":"tcp","outboundTag":"BLOCK"}`,
		`{"domain":["geosite:youtube","full:www.google.com"],"outboundTag":"YT"}`,
	}
	for index, want := range wantRules {
		if got := canonicalJSON(t, config.RouterConfig.RuleList[index]); got != canonicalJSON(t, []byte(want)) {
			t.Fatalf("routing rule %d = %s, want %s", index, got, canonicalJSON(t, []byte(want)))
		}
	}
	routerConfig, err := config.RouterConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	wantRouteTags := []string{"dns-out", "BLOCK", "BLOCK", "DIRECT", "BLOCK", "BLOCK", "YT"}
	for index, want := range wantRouteTags {
		if got := routerConfig.Rule[index].GetTag(); got != want {
			t.Fatalf("routing rule %d target = %q, want %q", index, got, want)
		}
	}
	if got := routerConfig.Rule[2].GetUserEmail(); len(got) != 1 || got[0] != "Mobile_user" {
		t.Fatalf("mobile-user route changed: %v", got)
	}
	if route := routerConfig.Rule[3].GetVlessRouteList(); route == nil || len(route.Range) != 1 || route.Range[0].From != 50 || route.Range[0].To != 50 {
		t.Fatalf("vlessRoute 50 contract changed: %v", route)
	}
	for _, rule := range routerConfig.Rule {
		if rule.GetTag() == "TORRENT" {
			t.Fatal("TORRENT unexpectedly became reachable; add an explicit runtime E2E before changing this assertion")
		}
	}

	if _, err := config.Build(); err != nil {
		t.Fatalf("corrected production config does not build: %v", err)
	}
}

func canonicalJSON(t *testing.T, source []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(source, &value); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func assertFreedomContract(t *testing.T, outbound *conf.OutboundDetourConfig, strategy, interfaceName string) {
	t.Helper()
	if outbound.Protocol != "freedom" || outbound.Settings == nil || outbound.StreamSetting == nil || outbound.StreamSetting.SocketSettings == nil {
		t.Fatalf("freedom outbound contract changed: %#v", outbound)
	}
	var settings conf.FreedomConfig
	if err := json.Unmarshal(*outbound.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.DomainStrategy != strategy || len(settings.FinalRules) != 0 {
		t.Fatalf("freedom settings = %#v, want strategy %q without test-only finalRules", settings, strategy)
	}
	socket := outbound.StreamSetting.SocketSettings
	if socket.Interface != interfaceName || socket.TFO != true {
		t.Fatalf("freedom socket contract changed: %#v", socket)
	}
}

func remnaNodeProductionConfig() []byte {
	return []byte(fmt.Sprintf(`{
  "log": {
    "error": "/var/log/remnanode/error.log",
    "access": "/var/log/remnanode/access.log",
    "loglevel": "warning"
  },
  "dns": {
    "tag": "dns_inbound",
    "servers": [
      "https+local://1.1.1.1/dns-query",
      "https+local://dns.google/dns-query",
      "1.1.1.1",
      "8.8.8.8"
    ],
    "disableCache": false,
    "queryStrategy": "UseIP",
    "disableFallback": false
  },
  "inbounds": [
    {
      "tag": "reality-pro-de-mux",
      "port": "443",
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {"flow": "", "clients": [], "decryption": "none"},
      "sniffing": {"enabled": true, "routeOnly": false, "destOverride": ["http", "tls"]},
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "xver": 2,
          "target": "/dev/shm/nginx.sock",
          "shortIds": [""],
          "privateKey": "%s",
          "serverNames": ["pro-de.emrata.top"]
        }
      }
    },
    {
      "tag": "reality-pro-de",
      "port": "8443",
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "sniffing": {"enabled": true, "routeOnly": false, "destOverride": ["http", "tls"]},
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "xver": 2,
          "target": "/dev/shm/nginx.sock",
          "shortIds": [""],
          "privateKey": "%s",
          "serverNames": ["pro-de.emrata.top"]
        }
      }
    }
  ],
  "outbounds": [
    {"tag": "DIRECT", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv4"}, "streamSettings": {"sockopt": {"tcpFastOpen": true}}},
    {"tag": "YT", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv6"}, "streamSettings": {"sockopt": {"interface": "yt", "tcpFastOpen": true}}},
    {"tag": "TORRENT", "protocol": "blackhole"},
    {"tag": "BLOCK", "protocol": "blackhole"},
    {"tag": "dns-out", "protocol": "dns"}
  ],
  "routing": {
    "rules": [
      {"port": "53", "network": "udp", "outboundTag": "dns-out"},
      {"port": "443", "network": "udp", "outboundTag": "BLOCK"},
      {"user": ["Mobile_user"], "outboundTag": "BLOCK"},
      {"domain": ["geosite:youtube", "full:www.google.com"], "vlessRoute": "50", "outboundTag": "DIRECT"},
      {"ip": ["geoip:private"], "outboundTag": "BLOCK"},
      {"port": "25", "network": "tcp", "outboundTag": "BLOCK"},
      {"domain": ["geosite:youtube", "full:www.google.com"], "outboundTag": "YT"}
    ],
    "domainStrategy": "IPIfNonMatch"
  }
}`, realityPrivateKey, realityPrivateKey))
}

func TestRemnaNodeConfigRejectsLiteralNoneFlow(t *testing.T) {
	config := []byte(`{"clients":[],"decryption":"none","flow":"none"}`)
	var inbound conf.VLessInboundConfig
	if err := json.Unmarshal(config, &inbound); err != nil {
		t.Fatal(err)
	}
	if _, err := inbound.Build(); err == nil || !strings.Contains(err.Error(), `settings.flow`) {
		t.Fatalf("literal none flow error = %v", err)
	}
}

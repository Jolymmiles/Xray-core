//go:build integration

package singmux_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVLESSTLSProfileCurveConfig(t *testing.T) {
	base := []byte(`{
		"inbounds": [{
			"streamSettings": {
				"security": "tls",
				"tlsSettings": {}
			}
		}]
	}`)

	encoded := vlessTLSProfileCurveConfig(t, base, []string{"X25519"})

	var config map[string]any
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	streamSettings := inbound["streamSettings"].(map[string]any)
	tlsSettings := streamSettings["tlsSettings"].(map[string]any)
	curves := tlsSettings["curvePreferences"].([]any)
	if len(curves) != 1 || curves[0] != "X25519" {
		t.Fatalf("curvePreferences = %#v, want [X25519]", curves)
	}
}

func TestVLESSTLSX25519ProcessMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level VLESS TLS X25519 compatibility matrix")
	}
	workDir := t.TempDir()
	binaries := buildE2EBinaries(t, workDir)
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, peer := range []string{"xray", "sing-box", "mihomo"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			t.Run(filepath.Join(peer, flowName), func(t *testing.T) {
				scenarioDir := t.TempDir()
				serverPort := freeTCPPort(t)
				socksPort := freeTCPPort(t)
				serverPath := filepath.Join(scenarioDir, "server.json")
				serverConfig := xrayVLESSTCPConfig(t, true, serverPort, 0, "tls", flow, certificate, privateKey, "")
				writeConfig(t, serverPath, vlessTLSProfileCurveConfig(t, serverConfig, []string{"X25519"}))
				server := startE2EProcess(t, binaries.xray, "run", "-config", serverPath)
				waitTCP(t, server, serverPort)

				clientBinary, clientArgs, clientConfig := vlessTCPClientConfig(
					t,
					binaries,
					peer,
					serverPort,
					socksPort,
					"tls",
					flow,
					certificate,
				)
				clientPath := filepath.Join(scenarioDir, "client"+configExtension(peer, peer == "xray"))
				clientArgs = replaceConfigPath(clientArgs, clientPath)
				writeConfig(t, clientPath, clientConfig)
				client := startReadyE2EClient(t, peer, clientBinary, clientArgs, socksPort)
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("server logs:\n%s", server.logs.String())
						t.Logf("client logs:\n%s", client.logs.String())
					}
				})
				testSOCKSTCP(t, socksPort, tcpEcho)
			})
		}
	}
}

func TestVLESSTLSServerProfile(t *testing.T) {
	if os.Getenv("XRAY_VLESS_TLS_PROFILE") != "1" {
		t.Skip("set XRAY_VLESS_TLS_PROFILE=1 to profile the VLESS TLS server")
	}

	profileDir := os.Getenv("XRAY_VLESS_TLS_PROFILE_DIR")
	if profileDir == "" {
		t.Fatal("XRAY_VLESS_TLS_PROFILE_DIR is required")
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}

	profileSeconds := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_SECONDS", 5)
	concurrency := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_CONCURRENCY", 16)
	drainMillis := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_DRAIN_MILLISECONDS", 1000)
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateVLESSTLSProfileCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, flow := range []string{"", "xtls-rprx-vision"} {
		flowName := "no-flow"
		if flow != "" {
			flowName = "vision"
		}
		t.Run(flowName, func(t *testing.T) {
			scenarioDir := t.TempDir()
			serverPort := freeTCPPort(t)
			socksPort := freeTCPPort(t)
			metricsPort := freeTCPPort(t)
			serverPath := filepath.Join(scenarioDir, "server.json")
			clientPath := filepath.Join(scenarioDir, "client.json")
			serverConfig := xrayVLESSTCPConfig(t, true, serverPort, 0, "tls", flow, certificate, privateKey, "")
			if value := strings.TrimSpace(os.Getenv("XRAY_VLESS_TLS_PROFILE_CURVES")); value != "" {
				serverConfig = vlessTLSProfileCurveConfig(t, serverConfig, strings.Split(value, ","))
			}
			writeConfig(t, serverPath, vlessTLSProfileConfig(t, serverConfig, metricsPort))
			writeConfig(t, clientPath, xrayVLESSTCPConfig(t, false, serverPort, socksPort, "tls", flow, certificate, "", ""))

			server := startE2EProcess(t, xray, "run", "-config", serverPath)
			waitTCP(t, server, serverPort)
			waitTCP(t, server, metricsPort)
			client := startE2EProcess(t, xray, "run", "-config", clientPath)
			waitSOCKS(t, client, socksPort)
			if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
				t.Fatalf("warm-up: %v", err)
			}

			var successful atomic.Uint64
			stop := make(chan struct{})
			loadErrors := make(chan error, 1)
			var workers sync.WaitGroup
			for range concurrency {
				workers.Add(1)
				go func() {
					defer workers.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
							select {
							case loadErrors <- err:
							default:
							}
							return
						}
						successful.Add(1)
					}
				}()
			}

			readinessDeadline := time.Now().Add(5 * time.Second)
			for successful.Load() == 0 && time.Now().Before(readinessDeadline) {
				time.Sleep(time.Millisecond)
			}
			if successful.Load() == 0 {
				close(stop)
				workers.Wait()
				select {
				case err := <-loadErrors:
					t.Fatalf("load did not become ready: %v", err)
				default:
					t.Fatal("load did not become ready")
				}
			}

			baseURL := fmt.Sprintf("http://127.0.0.1:%d", metricsPort)
			cpuPath := filepath.Join(profileDir, flowName+"-cpu.pb.gz")
			started := time.Now()
			profileErr := downloadVLESSTLSProfile(
				baseURL+"/debug/pprof/profile?seconds="+strconv.Itoa(profileSeconds),
				cpuPath,
			)
			elapsed := time.Since(started)
			close(stop)
			workers.Wait()
			if profileErr != nil {
				t.Fatal(profileErr)
			}
			select {
			case err := <-loadErrors:
				t.Fatalf("profile load failed: %v", err)
			default:
			}

			if err := downloadVLESSTLSProfile(
				baseURL+"/debug/pprof/goroutine",
				filepath.Join(profileDir, flowName+"-goroutine-immediate.pb.gz"),
			); err != nil {
				t.Error(err)
			}
			time.Sleep(time.Duration(drainMillis) * time.Millisecond)

			for _, profile := range []struct {
				name     string
				endpoint string
			}{
				{name: "heap.pb.gz", endpoint: "/debug/pprof/heap?gc=1"},
				{name: "heap-second-gc.pb.gz", endpoint: "/debug/pprof/heap?gc=1"},
				{name: "allocs.pb.gz", endpoint: "/debug/pprof/allocs"},
				{name: "goroutine.pb.gz", endpoint: "/debug/pprof/goroutine"},
			} {
				if err := downloadVLESSTLSProfile(
					baseURL+profile.endpoint,
					filepath.Join(profileDir, flowName+"-"+profile.name),
				); err != nil {
					t.Error(err)
				}
			}

			count := successful.Load()
			t.Logf(
				"VLESS TLS server profile mode=%s connections=%d duration=%s rate=%.1f connections/s profiles=%s",
				flowName,
				count,
				elapsed.Round(time.Millisecond),
				float64(count)/elapsed.Seconds(),
				profileDir,
			)
		})
	}
}

func TestVLESSTLSServerThroughputProfile(t *testing.T) {
	if os.Getenv("XRAY_VLESS_TLS_THROUGHPUT_PROFILE") != "1" {
		t.Skip("set XRAY_VLESS_TLS_THROUGHPUT_PROFILE=1 to profile established VLESS TLS streams")
	}

	profileDir := os.Getenv("XRAY_VLESS_TLS_PROFILE_DIR")
	if profileDir == "" {
		t.Fatal("XRAY_VLESS_TLS_PROFILE_DIR is required")
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}

	profileSeconds := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_SECONDS", 5)
	concurrency := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_CONCURRENCY", 4)
	payloadBytes := configuredVLESSTLSProfileInt(t, "XRAY_VLESS_TLS_PROFILE_PAYLOAD_BYTES", 64*1024)
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateVLESSTLSProfileCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, flow := range []string{"", "xtls-rprx-vision"} {
		flowName := "no-flow"
		if flow != "" {
			flowName = "vision"
		}
		t.Run(flowName, func(t *testing.T) {
			scenarioDir := t.TempDir()
			serverPort := freeTCPPort(t)
			socksPort := freeTCPPort(t)
			metricsPort := freeTCPPort(t)
			serverPath := filepath.Join(scenarioDir, "server.json")
			clientPath := filepath.Join(scenarioDir, "client.json")
			serverConfig := xrayVLESSTCPConfig(t, true, serverPort, 0, "tls", flow, certificate, privateKey, "")
			if value := strings.TrimSpace(os.Getenv("XRAY_VLESS_TLS_PROFILE_CURVES")); value != "" {
				serverConfig = vlessTLSProfileCurveConfig(t, serverConfig, strings.Split(value, ","))
			}
			writeConfig(t, serverPath, vlessTLSProfileConfig(t, serverConfig, metricsPort))
			writeConfig(t, clientPath, xrayVLESSTCPConfig(t, false, serverPort, socksPort, "tls", flow, certificate, "", ""))

			server := startE2EProcess(t, xray, "run", "-config", serverPath)
			waitTCP(t, server, serverPort)
			waitTCP(t, server, metricsPort)
			client := startE2EProcess(t, xray, "run", "-config", clientPath)
			waitSOCKS(t, client, socksPort)

			connections := make([]net.Conn, 0, concurrency)
			for range concurrency {
				connection, err := dialSOCKSTCPAttempt(socksPort, tcpEcho.IP.String(), tcpEcho.Port)
				if err != nil {
					t.Fatal(err)
				}
				if err := connection.SetDeadline(time.Time{}); err != nil {
					connection.Close()
					t.Fatal(err)
				}
				connections = append(connections, connection)
			}
			t.Cleanup(func() {
				for _, connection := range connections {
					_ = connection.Close()
				}
			})

			payload := make([]byte, payloadBytes)
			for index := range payload {
				payload[index] = byte(index)
			}
			response := make([]byte, len(payload))
			for _, connection := range connections {
				if err := roundTripVLESSTLSPayload(connection, payload, response); err != nil {
					t.Fatalf("warm-up established stream: %v", err)
				}
			}

			var transferred atomic.Uint64
			stop := make(chan struct{})
			loadErrors := make(chan error, 1)
			var workers sync.WaitGroup
			for _, connection := range connections {
				workers.Add(1)
				go func(connection net.Conn) {
					defer workers.Done()
					response := make([]byte, len(payload))
					for {
						select {
						case <-stop:
							return
						default:
						}
						if err := roundTripVLESSTLSPayload(connection, payload, response); err != nil {
							select {
							case loadErrors <- err:
							default:
							}
							return
						}
						transferred.Add(uint64(len(payload)))
					}
				}(connection)
			}

			baseURL := fmt.Sprintf("http://127.0.0.1:%d", metricsPort)
			cpuPath := filepath.Join(profileDir, flowName+"-cpu.pb.gz")
			started := time.Now()
			profileErr := downloadVLESSTLSProfile(
				baseURL+"/debug/pprof/profile?seconds="+strconv.Itoa(profileSeconds),
				cpuPath,
			)
			elapsed := time.Since(started)
			close(stop)
			workers.Wait()
			if profileErr != nil {
				t.Fatal(profileErr)
			}
			select {
			case err := <-loadErrors:
				t.Fatalf("throughput profile load failed: %v", err)
			default:
			}

			for _, profile := range []struct {
				name     string
				endpoint string
			}{
				{name: "heap.pb.gz", endpoint: "/debug/pprof/heap?gc=1"},
				{name: "heap-second-gc.pb.gz", endpoint: "/debug/pprof/heap?gc=1"},
				{name: "allocs.pb.gz", endpoint: "/debug/pprof/allocs"},
				{name: "goroutine.pb.gz", endpoint: "/debug/pprof/goroutine"},
			} {
				if err := downloadVLESSTLSProfile(
					baseURL+profile.endpoint,
					filepath.Join(profileDir, flowName+"-"+profile.name),
				); err != nil {
					t.Error(err)
				}
			}

			bytesTransferred := transferred.Load()
			t.Logf(
				"VLESS TLS established-stream profile mode=%s payload=%d concurrency=%d transferred=%d duration=%s throughput=%.1f MiB/s profiles=%s",
				flowName,
				payloadBytes,
				concurrency,
				bytesTransferred,
				elapsed.Round(time.Millisecond),
				float64(bytesTransferred)/elapsed.Seconds()/(1024*1024),
				profileDir,
			)
		})
	}
}

func roundTripVLESSTLSPayload(connection net.Conn, payload, response []byte) error {
	for remaining := payload; len(remaining) > 0; {
		written, err := connection.Write(remaining)
		if err != nil {
			return fmt.Errorf("write echo payload: %w", err)
		}
		remaining = remaining[written:]
	}
	if _, err := io.ReadFull(connection, response); err != nil {
		return fmt.Errorf("read echo payload: %w", err)
	}
	return nil
}

func BenchmarkVLESSTLSCertificateProcess(b *testing.B) {
	workDir := b.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		b.Fatal(err)
	}
	xray := buildE2EBinary(b, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	tcpEcho := startTCPEcho(b).(*net.TCPAddr)

	for _, keyType := range []string{"rsa", "ecdsa-p256"} {
		for _, mode := range []struct {
			name              string
			sessionResumption bool
			plainGoTLS        bool
		}{
			{name: "full-handshake"},
			{name: "resumption-default-utls", sessionResumption: true},
			{name: "resumption-go-tls", sessionResumption: true, plainGoTLS: true},
		} {
			b.Run(filepath.Join(keyType, mode.name), func(b *testing.B) {
				b.StopTimer()
				scenarioDir := b.TempDir()
				certificate, privateKey := generateVLESSTLSCertificate(b, scenarioDir, keyType)
				serverPort := freeTCPPort(b)
				socksPort := freeTCPPort(b)
				serverPath := filepath.Join(scenarioDir, "server.json")
				clientPath := filepath.Join(scenarioDir, "client.json")
				serverConfig := xrayVLESSTCPConfig(b, true, serverPort, 0, "tls", "", certificate, privateKey, "")
				clientConfig := xrayVLESSTCPConfig(b, false, serverPort, socksPort, "tls", "", certificate, "", "")
				writeConfig(b, serverPath, vlessTLSSessionResumptionConfig(b, serverConfig, mode.sessionResumption, false))
				writeConfig(b, clientPath, vlessTLSSessionResumptionConfig(b, clientConfig, mode.sessionResumption, mode.plainGoTLS))
				server := startE2EProcess(b, xray, "run", "-config", serverPath)
				waitTCP(b, server, serverPort)
				client := startE2EProcess(b, xray, "run", "-config", clientPath)
				waitSOCKS(b, client, socksPort)
				if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
					b.Fatalf("warm-up: %v", err)
				}

				b.ResetTimer()
				b.StartTimer()
				for b.Loop() {
					if err := runSOCKSTCP(socksPort, tcpEcho); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
			})
		}
	}
}

func generateVLESSTLSProfileCertificate(t testing.TB, directory string) (string, string) {
	t.Helper()
	keyType := os.Getenv("XRAY_VLESS_TLS_PROFILE_KEY_TYPE")
	if keyType == "" || keyType == "rsa" {
		keyType = "rsa"
	}
	return generateVLESSTLSCertificate(t, directory, keyType)
}

func generateVLESSTLSCertificate(t testing.TB, directory, keyType string) (string, string) {
	t.Helper()
	if keyType == "rsa" {
		return generateCertificate(t, directory)
	}
	if keyType != "ecdsa-p256" {
		t.Fatalf("XRAY_VLESS_TLS_PROFILE_KEY_TYPE=%q, want rsa or ecdsa-p256", keyType)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "server.crt")
	privateKeyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, privateKeyPath
}

func vlessTLSSessionResumptionConfig(t testing.TB, base []byte, enabled, plainGoTLS bool) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	for _, sectionName := range []string{"inbounds", "outbounds"} {
		section, _ := config[sectionName].([]any)
		for _, rawEntry := range section {
			entry, _ := rawEntry.(map[string]any)
			streamSettings, _ := entry["streamSettings"].(map[string]any)
			tlsSettings, _ := streamSettings["tlsSettings"].(map[string]any)
			if tlsSettings != nil {
				tlsSettings["enableSessionResumption"] = enabled
				if sectionName == "outbounds" && plainGoTLS {
					tlsSettings["fingerprint"] = "unsafe"
				}
			}
		}
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func vlessTLSProfileConfig(t *testing.T, base []byte, metricsPort int) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	config["metrics"] = map[string]any{
		"listen": "127.0.0.1:" + strconv.Itoa(metricsPort),
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func vlessTLSProfileCurveConfig(t testing.TB, base []byte, curvePreferences []string) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(base, &config); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		t.Fatal("profile config has no inbounds")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatal("profile config inbound is not an object")
	}
	streamSettings, ok := inbound["streamSettings"].(map[string]any)
	if !ok {
		t.Fatal("profile config inbound has no streamSettings")
	}
	tlsSettings, ok := streamSettings["tlsSettings"].(map[string]any)
	if !ok {
		t.Fatal("profile config inbound has no tlsSettings")
	}
	tlsSettings["curvePreferences"] = curvePreferences

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configuredVLESSTLSProfileInt(t *testing.T, name string, fallback int) int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		t.Fatalf("%s=%q is not a positive integer", name, value)
	}
	return parsed
}

func downloadVLESSTLSProfile(url, path string) error {
	response, err := http.Get(url) // #nosec G107 -- loopback-only test metrics endpoint
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %s", url, response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", url, err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

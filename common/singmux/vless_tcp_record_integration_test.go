//go:build integration

package singmux_test

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

const (
	tlsRecordTypeApplicationData = 23
	// TLS 1.3 AEAD record expansion: inner content type plus a 16-byte tag.
	tlsRecordExpansion = 1 + 16
	// The VLESS response header is the version byte and an empty addons length.
	vlessResponseHeaderLength = 2
)

// tlsRecordRelay forwards TCP between an Xray client and server and records
// the length of every TLS record in each direction.
type tlsRecordRelay struct {
	mu          sync.Mutex
	connections []*tlsRecordConnection
}

type tlsRecordConnection struct {
	mu         sync.Mutex
	fromClient []tlsRecord
	fromServer []tlsRecord
}

type tlsRecord struct {
	contentType byte
	length      int
}

func startTLSRecordRelay(t *testing.T, serverPort int) (*tlsRecordRelay, int) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := new(tlsRecordRelay)
	var group sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		group.Wait()
	})
	group.Go(func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))
			if err != nil {
				_ = client.Close()
				continue
			}
			connection := new(tlsRecordConnection)
			relay.mu.Lock()
			relay.connections = append(relay.connections, connection)
			relay.mu.Unlock()
			group.Go(func() {
				defer server.Close()
				copyTLSRecords(server, client, connection, &connection.fromClient)
			})
			group.Go(func() {
				defer client.Close()
				copyTLSRecords(client, server, connection, &connection.fromServer)
			})
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
		}
	})
	return relay, listener.Addr().(*net.TCPAddr).Port
}

func copyTLSRecords(destination io.Writer, source io.Reader, connection *tlsRecordConnection, records *[]tlsRecord) {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(source, header); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(source, body); err != nil {
			return
		}
		connection.mu.Lock()
		*records = append(*records, tlsRecord{contentType: header[0], length: len(body)})
		connection.mu.Unlock()
		if _, err := destination.Write(append(header, body...)); err != nil {
			return
		}
	}
}

func (r *tlsRecordRelay) snapshot() [][2][]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := make([][2][]int, 0, len(r.connections))
	for _, connection := range r.connections {
		connection.mu.Lock()
		snapshot = append(snapshot, [2][]int{
			applicationDataLengths(connection.fromClient),
			applicationDataLengths(connection.fromServer),
		})
		connection.mu.Unlock()
	}
	return snapshot
}

func applicationDataLengths(records []tlsRecord) []int {
	var lengths []int
	for _, record := range records {
		if record.contentType == tlsRecordTypeApplicationData {
			lengths = append(lengths, record.length)
		}
	}
	return lengths
}

// TestVLESSTCPHeaderSharesTLSRecordWithFirstPayload guards the record sizes a
// passive censor sees right after the TLS or REALITY handshake. Stock Xray
// sends the VLESS request header and the first payload in one record, and
// the response header with the first response payload; a header in its own
// record is a fixed-size record (61 bytes for a Vision request, 19 for any
// response) that stock Xray never produces.
func TestVLESSTCPHeaderSharesTLSRecordWithFirstPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("process-level VLESS TLS record sizes")
	}
	workDir := t.TempDir()
	xrayRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	xray := buildE2EBinary(t, "XRAY_E2E_BIN", filepath.Join(workDir, "xray"), xrayRoot, "./main")
	certificate, privateKey := generateCertificate(t, workDir)
	tcpEcho := startTCPEcho(t).(*net.TCPAddr)

	for _, security := range []string{"tls", "reality"} {
		for _, flow := range []string{"", "xtls-rprx-vision"} {
			flowName := "no-flow"
			if flow != "" {
				flowName = "vision"
			}
			t.Run(filepath.Join(security, flowName), func(t *testing.T) {
				scenarioDir := t.TempDir()
				serverPort := freeTCPPort(t)
				socksPort := freeTCPUDPPort(t)
				realityTarget := ""
				if security == "reality" {
					realityTarget = startRealityCoverServer(t, certificate, privateKey)
				}
				relay, relayPort := startTLSRecordRelay(t, serverPort)
				serverPath := filepath.Join(scenarioDir, "server.json")
				clientPath := filepath.Join(scenarioDir, "client.json")
				writeConfig(t, serverPath, xrayVLESSTCPConfig(t, true, serverPort, 0, security, flow, certificate, privateKey, realityTarget))
				writeConfig(t, clientPath, withSOCKSSniffing(t, xrayVLESSTCPConfig(t, false, relayPort, socksPort, security, flow, certificate, "", "")))
				server := startE2EProcess(t, xray, "run", "-config", serverPath)
				waitTCP(t, server, serverPort)
				client := startE2EProcess(t, xray, "run", "-config", clientPath)
				waitSOCKS(t, client, socksPort)
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("server logs:\n%s", server.logs.String())
						t.Logf("client logs:\n%s", client.logs.String())
					}
				})

				// Taken once the echo is back and before the client closes,
				// so no close_notify is among the records.
				var records [][2][]int
				testSOCKSTCP(t, socksPort, tcpEcho, func() { records = relay.snapshot() })
				if len(records) != 1 {
					t.Fatalf("relayed %d connections %v, want 1", len(records), records)
				}
				fromClient, fromServer := records[0][0], records[0][1]
				// The first client record is its encrypted Finished message.
				if len(fromClient) != 2 {
					t.Errorf("client application-data records %v: want the Finished record and one record with header and payload", fromClient)
				}
				for _, length := range fromServer {
					if length == vlessResponseHeaderLength+tlsRecordExpansion {
						t.Errorf("server application-data records %v: the response header went out in its own record", fromServer)
						break
					}
				}
			})
		}
	}
}

// withSOCKSSniffing turns on sniffing for the client's SOCKS inbound. Without
// it the outbound does not wait for the first payload before it sends the
// request header, a separate defect this test does not cover.
func withSOCKSSniffing(t *testing.T, config []byte) []byte {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	inbound := decoded["inbounds"].([]any)[0].(map[string]any)
	inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

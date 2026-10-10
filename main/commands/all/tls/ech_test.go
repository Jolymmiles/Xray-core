package tls

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

// runECH runs `xray tls ech args...` in a child copy of this test binary, since
// the command exits the process on errors, and returns its output and exit code.
// A child that does not finish within a minute is killed and fails the test.
func runECH(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestECHCommandProcess$")
	command.Env = append(os.Environ(), "XRAY_TEST_ECH_ARGS="+strings.Join(args, "\n"))
	var out, errOut bytes.Buffer
	command.Stdout = &out
	command.Stderr = &errOut
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("`xray tls ech %s` did not finish within a minute: %v", strings.Join(args, " "), err)
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exitCode = exitErr.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), exitCode
}

// TestECHCommandProcess is the child process of runECH.
func TestECHCommandProcess(t *testing.T) {
	raw, ok := os.LookupEnv("XRAY_TEST_ECH_ARGS")
	if !ok {
		t.Skip("child process of runECH")
	}
	var args []string
	if raw != "" {
		args = strings.Split(raw, "\n")
	}
	if err := cmdECH.Flag.Parse(args); err != nil {
		os.Exit(2)
	}
	executeECH(cmdECH, cmdECH.Flag.Args())
	os.Exit(0)
}

// echOutput is what a successful `xray tls ech` prints without --pem.
type echOutput struct {
	configList []byte
	serverKeys []byte
}

// parseECHOutput decodes the base64 ECH config list and server keys that
// `xray tls ech` prints.
func parseECHOutput(t *testing.T, stdout string) echOutput {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 || strings.TrimSpace(lines[0]) != "ECH config list:" || strings.TrimSpace(lines[2]) != "ECH server keys:" {
		t.Fatalf("unexpected `xray tls ech` output:\n%s", stdout)
	}
	configList, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil {
		t.Fatal(err)
	}
	return echOutput{configList: configList, serverKeys: serverKeys}
}

// echConfigFields are the ECHConfig fields the command chooses (RFC 9849,
// Section 4).
type echConfigFields struct {
	configID      uint8
	maxNameLength uint8
	publicName    string
}

// parseECHConfigList returns the config ID, maximum name length and public
// name of each ECHConfig in list (RFC 9849, Section 4).
func parseECHConfigList(t *testing.T, list []byte) []echConfigFields {
	t.Helper()
	s := cryptobyte.String(list)
	var configs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&configs) || !s.Empty() {
		t.Fatalf("malformed ECHConfigList %x", list)
	}
	var fields []echConfigFields
	for !configs.Empty() {
		var version uint16
		var contents, publicKey, suites, publicName, extensions cryptobyte.String
		var config echConfigFields
		var kem uint16
		if !configs.ReadUint16(&version) || !configs.ReadUint16LengthPrefixed(&contents) ||
			!contents.ReadUint8(&config.configID) || !contents.ReadUint16(&kem) ||
			!contents.ReadUint16LengthPrefixed(&publicKey) || !contents.ReadUint16LengthPrefixed(&suites) ||
			!contents.ReadUint8(&config.maxNameLength) || !contents.ReadUint8LengthPrefixed(&publicName) ||
			!contents.ReadUint16LengthPrefixed(&extensions) || !contents.Empty() || version != 0xfe0d {
			t.Fatalf("malformed ECHConfig in %x", list)
		}
		config.publicName = string(publicName)
		fields = append(fields, config)
	}
	return fields
}

// ECH clients ignore a config whose public name is not a DNS name or whose
// final label reads as a number, in decimal or as 0x and hexadecimal digits
// (RFC 9849, Section 6.1.7), and fall back to a cleartext SNI, so `xray tls
// ech` must refuse such names.
func TestECHRejectsPublicNamesClientsIgnore(t *testing.T) {
	for _, name := range []string{
		"192.0.2.1",
		"2001:db8::1",
		"example.com:443",
		"example.com.",
		"localhost",
		"example.123",
		"example.0x01",
		"example.0X1F",
		"example.0x",
		"-bad.example.com",
		"bad_label.example.com",
		"bücher.example",
		"https://example.com",
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, exitCode := runECH(t, "--serverName", name)
			if exitCode == 0 || strings.Contains(stdout, "ECH config list") {
				t.Fatalf("`xray tls ech --serverName %s` exited %d and printed:\n%s%s", name, exitCode, stdout, stderr)
			}
		})
	}
}

// A final label that only starts like a hexadecimal number is a DNS label like
// any other, and the config keeps it as the public name.
func TestECHAcceptsFinalLabelsThatAreNotNumbers(t *testing.T) {
	for _, name := range []string{"public.0xg1", "public.0x1g", "public.x01"} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, exitCode := runECH(t, "--serverName", name)
			if exitCode != 0 {
				t.Fatalf("`xray tls ech --serverName %s` exited %d: %s", name, exitCode, stderr)
			}
			configs := parseECHConfigList(t, parseECHOutput(t, stdout).configList)
			if len(configs) != 1 || configs[0].publicName != name {
				t.Fatalf("configs = %+v, want one with public name %q", configs, name)
			}
		})
	}
}

// The config ID travels in cleartext in the outer ClientHello, so a fixed
// default would mark every config the command generates.
func TestECHPicksRandomConfigID(t *testing.T) {
	ids := make(map[uint8]bool)
	for range 8 {
		stdout, stderr, exitCode := runECH(t)
		if exitCode != 0 {
			t.Fatalf("`xray tls ech` exited %d: %s", exitCode, stderr)
		}
		for _, config := range parseECHConfigList(t, parseECHOutput(t, stdout).configList) {
			ids[config.configID] = true
		}
	}
	if len(ids) < 2 {
		t.Fatalf("eight generated configs share config IDs %v", ids)
	}
}

// An explicit --configId and --maxNameLength end up in the generated
// ECHConfig.
func TestECHHonorsConfigIDAndMaxNameLength(t *testing.T) {
	stdout, stderr, exitCode := runECH(t, "--serverName", "public.example.com", "--configId", "7", "--maxNameLength", "42")
	if exitCode != 0 {
		t.Fatalf("`xray tls ech` exited %d: %s", exitCode, stderr)
	}
	configs := parseECHConfigList(t, parseECHOutput(t, stdout).configList)
	want := echConfigFields{configID: 7, maxNameLength: 42, publicName: "public.example.com"}
	if len(configs) != 1 || configs[0] != want {
		t.Fatalf("configs = %+v, want [%+v]", configs, want)
	}

	for _, args := range [][]string{{"--configId", "256"}, {"--configId", "-2"}, {"--maxNameLength", "256"}, {"--maxNameLength", "-1"}} {
		if _, _, exitCode := runECH(t, args...); exitCode == 0 {
			t.Errorf("`xray tls ech %s` succeeded", strings.Join(args, " "))
		}
	}
}

// The generated keys and config list must work as a pair in a real TLS 1.3
// handshake with ECH.
func TestECHKeysCompleteHandshake(t *testing.T) {
	stdout, stderr, exitCode := runECH(t, "--serverName", "public.example.com")
	if exitCode != 0 {
		t.Fatalf("`xray tls ech` exited %d: %s", exitCode, stderr)
	}
	output := parseECHOutput(t, stdout)
	keys, err := xtls.ConvertToGoECHKeys(output.serverKeys)
	if err != nil {
		t.Fatal(err)
	}

	generated, _ := cert.MustGenerate(nil, cert.CommonName("inner.example.com"), cert.DNSNames("inner.example.com"))
	privateKey, err := x509.ParsePKCS8PrivateKey(generated.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &gotls.Config{
		Certificates:             []gotls.Certificate{{Certificate: [][]byte{generated.Certificate}, PrivateKey: privateKey}},
		EncryptedClientHelloKeys: keys,
		MinVersion:               gotls.VersionTLS13,
	}
	clientConfig := &gotls.Config{
		ServerName:                     "inner.example.com",
		InsecureSkipVerify:             true, // #nosec G402 -- generated test certificate
		EncryptedClientHelloConfigList: output.configList,
		MinVersion:                     gotls.VersionTLS13,
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- gotls.Server(serverConn, serverConfig).HandshakeContext(ctx) }()
	client := gotls.Client(clientConn, clientConfig)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !client.ConnectionState().ECHAccepted {
		t.Fatal("the server did not accept ECH with the generated keys")
	}
}

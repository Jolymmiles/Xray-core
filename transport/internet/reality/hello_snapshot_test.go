package reality

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"flag"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"testing/cryptotest"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
)

var updateHelloSnapshot = flag.Bool("update-hello-snapshot", false, "rewrite testdata/client_hello_snapshot.json")

// emitREALITYHello sends the first ClientHello of UClient for the named
// fingerprint and returns its record with the sealed session ID, which holds
// the time, zeroed. A panic is reported as the outcome.
func emitREALITYHello(name string, publicKey []byte) (record []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			record, err = nil, fmt.Errorf("panic: %v", recovered)
		}
	}()
	capture := &hellotest.Capture{}
	_, handshakeErr := UClient(capture, &Config{
		ServerName:  "example.com",
		Fingerprint: name,
		PublicKey:   publicKey,
		ShortId:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}, context.Background(), net.TCPDestination(net.DomainAddress("example.com"), 443))
	record, err = capture.FirstRecord()
	if err != nil && handshakeErr != nil {
		// What failed, not where: building the hello may fail before or
		// during the handshake.
		return nil, handshakeErr
	}
	if err != nil {
		return nil, err
	}
	clear(record[hellotest.SessionIDOffset : hellotest.SessionIDOffset+32])
	return record, nil
}

// TestREALITYClientHelloSnapshot pins the first ClientHello UClient sends for
// every fingerprint a REALITY client may select, as
// transport/internet/tls/hello_snapshot_test.go does for TLS. Regenerate with
// -update-hello-snapshot only for an intended change.
func TestREALITYClientHelloSnapshot(t *testing.T) {
	privateKey, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()

	names := make(map[string]bool)
	for _, registry := range []map[string]*utls.ClientHelloID{
		tls.PresetFingerprints, tls.ModernFingerprints, tls.OtherFingerprints,
	} {
		for name := range registry {
			names[name] = true
		}
	}
	// The REALITY settings reject these; "random" is one of the Modern
	// fingerprints.
	for _, name := range []string{"unsafe", "hellogolang", "random"} {
		delete(names, name)
	}
	// The randomized presets draw their seed at startup; register a copy per
	// fixed seed under its own name for the length of the test.
	for _, preset := range []string{"randomized", "randomizednoalpn"} {
		delete(names, preset)
		for _, seed := range randomizedSeeds {
			decoded, _ := hex.DecodeString(seed.seed)
			seeded := *tls.GetFingerprint(preset)
			seeded.Seed = (*utls.PRNGSeed)(decoded)
			name := preset + "@" + seed.seed[:8]
			tls.OtherFingerprints[name] = &seeded
			t.Cleanup(func() { delete(tls.OtherFingerprints, name) })
			names[name] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	snapshot := func(t *testing.T, name string) hellotest.Snapshot {
		cryptotest.SetGlobalRandom(t, 1)
		record, err := emitREALITYHello(name, publicKey)
		if err != nil {
			return hellotest.Snapshot{Error: err.Error()}
		}
		summary, err := hellotest.Summarize(record)
		if err != nil {
			t.Fatal(err)
		}
		return summary
	}
	got := make(map[string]hellotest.Snapshot)
	for _, name := range sorted {
		t.Run(name, func(t *testing.T) {
			first := snapshot(t, name)
			if again := snapshot(t, name); !reflect.DeepEqual(first, again) {
				t.Fatalf("ClientHello is not reproducible under fixed randomness:\n%+v\n%+v", first, again)
			}
			got[name] = first
		})
	}
	hellotest.Compare(t, "testdata/client_hello_snapshot.json", got, *updateHelloSnapshot)
}

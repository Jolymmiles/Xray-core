package tls_test

import (
	"context"
	gotls "crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"slices"
	"sort"
	"testing"
	"testing/cryptotest"

	utls "github.com/refraction-networking/utls"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/tls/hellotest"
)

var updateHelloSnapshot = flag.Bool("update-hello-snapshot", false, "rewrite testdata/client_hello_snapshot.json")

const helloSnapshotFile = "testdata/client_hello_snapshot.json"

// snapshotFlags passes -update-hello-snapshot on to the isolated child.
func snapshotFlags() []string {
	if *updateHelloSnapshot {
		return []string{"-update-hello-snapshot"}
	}
	return nil
}

// snapshotSeeds are fixed seeds for the fingerprints Xray draws a seed for at
// startup. They are the seeds of randomized_seeds_test.go.
func snapshotSeeds() map[string]*utls.PRNGSeed {
	seeds := make(map[string]*utls.PRNGSeed)
	for _, seed := range randomizedSeeds {
		decoded, _ := hex.DecodeString(seed.seed)
		seeds[seed.seed[:8]] = (*utls.PRNGSeed)(decoded)
	}
	return seeds
}

// snapshotFingerprints returns every selectable fingerprint by name. The
// randomized presets appear once per fixed seed; "random" is one of the
// Modern fingerprints and is checked to be one; "unsafe" is not uTLS.
func snapshotFingerprints(t *testing.T) map[string]utls.ClientHelloID {
	t.Helper()
	fingerprints := make(map[string]utls.ClientHelloID)
	for _, registry := range []map[string]*utls.ClientHelloID{
		xraytls.PresetFingerprints, xraytls.ModernFingerprints, xraytls.OtherFingerprints,
	} {
		for name, id := range registry {
			switch name {
			case "unsafe":
				continue
			case "random":
				found := false
				for _, modern := range xraytls.ModernFingerprints {
					found = found || modern == id
				}
				if !found {
					t.Fatalf("random is not one of the Modern fingerprints")
				}
				continue
			case "randomized", "randomizednoalpn":
				for short, seed := range snapshotSeeds() {
					seeded := *id
					seeded.Seed = seed
					fingerprints[name+"@"+short] = seeded
				}
				continue
			}
			fingerprints[name] = *id
		}
	}
	return fingerprints
}

type helloPath struct {
	name   string
	config func() *gotls.Config
	// http11 sends the outer ALPN of the WebSocket and HTTPUpgrade dialers.
	http11 bool
}

var helloPaths = []helloPath{
	{name: "stock", config: func() *gotls.Config {
		return &gotls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}
	}},
	{name: "http11", http11: true, config: func() *gotls.Config {
		return &gotls.Config{ServerName: "example.com", NextProtos: []string{"http/1.1"}}
	}},
	{name: "http11-resumption", http11: true, config: func() *gotls.Config {
		return &gotls.Config{
			ServerName:         "example.com",
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: gotls.NewLRUClientSessionCache(1),
		}
	}},
	{name: "resumption", config: func() *gotls.Config {
		return &gotls.Config{
			ServerName:         "example.com",
			NextProtos:         []string{"h2", "http/1.1"},
			ClientSessionCache: gotls.NewLRUClientSessionCache(1),
		}
	}},
}

// emitClientHello sends the first ClientHello of fingerprint along path the
// way Xray's TLS dialers do, and returns its record.
func emitClientHello(path helloPath, fingerprint utls.ClientHelloID) ([]byte, error) {
	capture := &hellotest.Capture{}
	var options []xraytls.UClientOption
	if path.http11 {
		options = append(options, xraytls.WithHTTP11ALPN())
	}
	_, err := xraytls.ClientHandshake(context.Background(), capture, path.config(), &fingerprint, options...)
	record, recordErr := capture.FirstRecord()
	if recordErr != nil && err != nil {
		// What failed, not where: building the hello may fail before or
		// during the handshake.
		return nil, err
	}
	return record, recordErr
}

func snapshotHello(t *testing.T, path helloPath, fingerprint utls.ClientHelloID) hellotest.Snapshot {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 1)
	record, err := emitClientHello(path, fingerprint)
	if err != nil {
		return hellotest.Snapshot{Error: err.Error()}
	}
	snapshot, err := hellotest.Summarize(record)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// TestClientHelloSnapshot pins the exact first ClientHello Xray sends for
// every selectable fingerprint on each construction path. Randomness is
// fixed for the whole process, so any change to how or when the hello is
// built shows as a byte difference. Regenerate with -update-hello-snapshot
// only for an intended change, and review the summary diff.
func TestClientHelloSnapshot(t *testing.T) {
	if !hellotest.Isolated(t, snapshotFlags()...) {
		return
	}
	fingerprints := snapshotFingerprints(t)
	names := make([]string, 0, len(fingerprints))
	for name := range fingerprints {
		names = append(names, name)
	}
	sort.Strings(names)

	got := make(map[string]hellotest.Snapshot)
	for _, path := range helloPaths {
		for _, name := range names {
			key := path.name + "/" + name
			t.Run(key, func(t *testing.T) {
				first := snapshotHello(t, path, fingerprints[name])
				if again := snapshotHello(t, path, fingerprints[name]); !reflect.DeepEqual(first, again) {
					t.Fatalf("ClientHello is not reproducible under fixed randomness:\n%+v\n%+v", first, again)
				}
				got[key] = first
			})
		}
	}

	hellotest.Compare(t, helloSnapshotFile, got, *updateHelloSnapshot)
}

// TestFirefoxHelloIgnoresSessionCache pins that a session cache without a
// ticket leaves the first ClientHello of the firefox aliases as it is without
// a cache: only a ticket changes it. TestClientHelloSnapshot holds every row
// of the golden file to what Xray sends.
func TestFirefoxHelloIgnoresSessionCache(t *testing.T) {
	data, err := os.ReadFile(helloSnapshotFile)
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]hellotest.Snapshot
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"firefox", "hellofirefox_auto"} {
		for _, paths := range [][2]string{{"stock", "resumption"}, {"http11", "http11-resumption"}} {
			without, with := golden[paths[0]+"/"+name], golden[paths[1]+"/"+name]
			if without.SHA256 == "" || !reflect.DeepEqual(without, with) {
				t.Errorf("%s: %s and %s differ or are missing:\n%+v\n%+v", name, paths[0], paths[1], without, with)
			}
		}
	}
}

// TestHelloOffersALPSOnlyForItsALPN pins that no ClientHello offers
// application settings for a protocol its ALPN leaves out. Chromium adds
// ALPS for the protocols it puts in ALPN, so a WebSocket or HTTPUpgrade
// hello, which offers http/1.1 alone, carries no ALPS extension, while the
// same fingerprint keeps ALPS for h2 wherever it offers h2.
func TestHelloOffersALPSOnlyForItsALPN(t *testing.T) {
	browserLike := helloPath{name: "http11-browser-alpn", http11: true, config: func() *gotls.Config {
		return &gotls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}
	}}
	withALPS := make(map[string]int)
	for name, fingerprint := range snapshotFingerprints(t) {
		for _, path := range append([]helloPath{browserLike}, helloPaths...) {
			record, err := emitClientHello(path, fingerprint)
			if err != nil {
				continue // a fingerprint that cannot build its hello on this path
			}
			hello, err := hellotest.Summarize(record)
			if err != nil {
				t.Fatalf("%s/%s: %v", path.name, name, err)
			}
			for _, protocol := range hello.ALPS {
				if !slices.Contains(hello.ALPN, protocol) {
					t.Errorf("%s/%s: ALPS for %q, ALPN %q", path.name, name, protocol, hello.ALPN)
				}
			}
			// Both codepoints: 17513 until Chrome 131, 17613 since.
			sent := slices.Contains(hello.Extensions, 17513) || slices.Contains(hello.Extensions, 17613)
			if sent && len(hello.ALPS) == 0 {
				t.Errorf("%s/%s: an ALPS extension without a protocol, ALPN %q", path.name, name, hello.ALPN)
			}
			if sent {
				withALPS[path.name]++
			}
		}
	}
	// The rule must not hold by dropping ALPS everywhere.
	for _, path := range []string{"stock", "resumption", browserLike.name} {
		if withALPS[path] == 0 {
			t.Errorf("no fingerprint offers ALPS on the %s path", path)
		}
	}
}

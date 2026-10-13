package tls_test

import (
	"context"
	gotls "crypto/tls"
	"encoding/hex"
	"flag"
	"reflect"
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

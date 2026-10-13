package tls_test

import (
	"encoding/hex"
	"testing"

	utls "github.com/refraction-networking/utls"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// randomizedSeeds are fixed seeds for the presets Xray draws a seed for at
// startup. With the stock uTLS generator and the weights Xray used to give
// it, they draw each combination of X25519MLKEM768 in supported_groups and
// its key share: uTLS draws the two independently, and one bad draw broke a
// client until it restarted.
var randomizedSeeds = []struct {
	name, seed string
}{
	{"hybrid group and key share", "601028d9604f1e4dbb1898ce3a20a09949e7a0ff1006d2261f2adada0fdb0578"},
	{"hybrid group without key share", "417dcd23baffdb629c8f220af5b644b53732d59ac67524aa3c00b04482b1dab1"},
	{"hybrid key share without group", "4f4f221b2c049b52426343c0f90fd4d260e94821c1910cd4f0fd029d59211057"},
	{"classic groups and key shares", "32b8ac4901174b2856e670e893f5568c8a0bab62dcd1e030c21290161c750b27"},
}

var randomizedPresets = []string{"randomized", "randomizednoalpn"}

// randomizedFingerprint returns the preset an operator selects by name, with
// the seed Xray would have drawn at startup replaced by a fixed one.
func randomizedFingerprint(t *testing.T, preset, seed string) *utls.ClientHelloID {
	t.Helper()
	id := *xraytls.GetFingerprint(preset)
	decoded, err := hex.DecodeString(seed)
	if err != nil || len(decoded) != utls.PRNGSeedLength {
		t.Fatalf("bad seed %q: %v", seed, err)
	}
	id.Seed = (*utls.PRNGSeed)(decoded)
	return &id
}

package reality

import (
	"encoding/hex"
	"fmt"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// A randomized preset draws its seed once per process, so a seed the server
// turns away keeps that client off REALITY until it restarts.
func TestREALITYRandomizedFingerprintAuthenticates(t *testing.T) {
	for _, preset := range []string{"randomized", "randomizednoalpn"} {
		for _, seed := range randomizedSeeds {
			for _, requireMLKEM := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/requireMlkem=%v", preset, seed.name, requireMLKEM), func(t *testing.T) {
					fingerprint := *tls.GetFingerprint(preset)
					decoded, err := hex.DecodeString(seed.seed)
					if err != nil || len(decoded) != utls.PRNGSeedLength {
						t.Fatalf("bad seed %q: %v", seed.seed, err)
					}
					fingerprint.Seed = (*utls.PRNGSeed)(decoded)
					got := runKeyShareHandshake(t, fingerprint, keepHello, requireMLKEM)
					if !got.serverAccepted || !got.clientVerified {
						t.Fatalf("server accepted = %v, client verified = %v, want both true", got.serverAccepted, got.clientVerified)
					}
				})
			}
		}
	}
}

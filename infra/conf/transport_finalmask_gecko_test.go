package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

// Gecko (salamander with packetSize) splits packets into chunks whose message
// ID repeats every 256 messages and no field ties a chunk to its message, so
// after a lost chunk the receiver can still deliver a packet spliced from two.
// It may only sit below a transport that authenticates whole datagrams: QUIC,
// or mKCP with an mkcp-legacy integrity mask outside it (listed before it).
func TestGeckoRequiresDatagramIntegrity(t *testing.T) {
	const (
		gecko      = `{"type": "salamander", "settings": {"password": "gecko", "packetSize": "512-1200"}}`
		salamander = `{"type": "salamander", "settings": {"password": "plain"}}`
		checksum   = `{"type": "mkcp-legacy"}`
		aead       = `{"type": "mkcp-legacy", "settings": {"value": "seed"}}`
		dnsHeader  = `{"type": "mkcp-legacy", "settings": {"header": "dns"}}`
	)
	for _, tc := range []struct {
		name, network, masks string
		accept               bool
	}{
		{"hysteria", "hysteria", gecko, true},
		{"xhttp", "xhttp", gecko, true},
		{"masque", "masque", gecko, true},
		{"mkcp with the checksum mask outside", "kcp", checksum + "," + gecko, true},
		{"mkcp with the AEAD mask outside", "kcp", aead + "," + gecko, true},
		{"mkcp with xdns innermost", "kcp", aead + "," + gecko + "," + testXDNSMask, true},
		{"mkcp with plain salamander", "kcp", salamander, true},
		{"raw with plain salamander", "raw", salamander, true},
		{"bare mkcp", "kcp", gecko, false},
		{"mkcp with the integrity mask inside", "kcp", gecko + "," + checksum, false},
		{"mkcp with a header that does not check integrity", "kcp", dnsHeader + "," + gecko, false},
		{"raw", "raw", gecko, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var config StreamConfig
			if err := json.Unmarshal([]byte(`{"network": "`+tc.network+`", "finalmask": {"udp": [`+tc.masks+`]}}`), &config); err != nil {
				t.Fatal(err)
			}
			_, err := config.Build()
			switch {
			case tc.accept && err != nil:
				t.Fatalf("rejected: %v", err)
			case !tc.accept && err == nil:
				t.Fatal("accepted Gecko below a transport without datagram integrity")
			case !tc.accept && !strings.Contains(err.Error(), "packetSize"):
				t.Fatalf("error %q does not name packetSize", err)
			}
		})
	}
}

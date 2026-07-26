package tls

import (
	"reflect"
	"sort"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// extensionTypeNames identifies the extensions of a ClientHello template by
// concrete type. That is the granularity a JA3/JA4 observer sees: which
// extensions are offered, and in which order.
func extensionTypeNames(extensions []utls.TLSExtension) []string {
	names := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		names = append(names, reflect.TypeOf(extension).String())
	}
	return names
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

const pskExtensionTypeName = "*tls.UtlsPreSharedKeyExtension"

// stockSpec resolves one concrete ClientHello template. Randomized presets
// return a different template on every call, so every assertion must be made
// against this exact value rather than a fresh sample.
func stockSpec(t *testing.T, name string, id utls.ClientHelloID) utls.ClientHelloSpec {
	t.Helper()

	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Skipf("uTLS has no spec for %s: %v", name, err)
	}
	return spec
}

// namedFingerprints returns every fingerprint an operator can select, so a new
// preset cannot silently bypass this gate.
func namedFingerprints(t *testing.T) map[string]utls.ClientHelloID {
	t.Helper()

	all := make(map[string]utls.ClientHelloID)
	for _, registry := range []map[string]*utls.ClientHelloID{
		PresetFingerprints, ModernFingerprints, OtherFingerprints,
	} {
		for name, id := range registry {
			if id == nil {
				continue // resolved at startup or handled outside uTLS
			}
			all[name] = *id
		}
	}
	if len(all) == 0 {
		t.Fatal("no fingerprints registered")
	}
	return all
}

// TestResumptionNeverForgesFingerprint is the fidelity gate for session
// resumption. Enabling resumption may conceal or reveal pre_shared_key, which
// is what a real browser does once it holds a ticket. It must never add any
// other extension: doing so produces a ClientHello that matches no real
// browser, which is precisely what uTLS exists to avoid.
//
// See transport/internet/tls/SESSION_RESUMPTION_REVIEW.md section 4.
func TestResumptionNeverForgesFingerprint(t *testing.T) {
	for name, id := range namedFingerprints(t) {
		t.Run(name, func(t *testing.T) {
			stock := stockSpec(t, name, id)

			spec, ok := resumptionSpec(stock)
			if !ok {
				if spec != nil {
					t.Error("declined resumption but still returned a spec")
				}
				return // native fingerprint is used unchanged
			}

			stockTypes := extensionTypeNames(stock.Extensions)
			specTypes := extensionTypeNames(spec.Extensions)

			// Only pre_shared_key may be introduced, and only at the end.
			want := append([]string(nil), stockTypes...)
			if len(specTypes) == len(stockTypes)+1 {
				if last := specTypes[len(specTypes)-1]; last != pskExtensionTypeName {
					t.Fatalf("appended %s, want %s as the only addition", last, pskExtensionTypeName)
				}
				want = append(want, pskExtensionTypeName)
			}

			if got, wantSorted := sortedCopy(specTypes), sortedCopy(want); !reflect.DeepEqual(got, wantSorted) {
				t.Fatalf("extension set changed\n stock: %v\n  spec: %v", stockTypes, specTypes)
			}
		})
	}
}

// TestResumptionKeepsPreSharedKeyLast pins RFC 8446 section 4.2.11: when
// pre_shared_key is offered it must be the final ClientHello extension.
func TestResumptionKeepsPreSharedKeyLast(t *testing.T) {
	for name, id := range namedFingerprints(t) {
		t.Run(name, func(t *testing.T) {
			spec, ok := resumptionSpec(stockSpec(t, name, id))
			if !ok {
				return
			}
			types := extensionTypeNames(spec.Extensions)
			for i, extensionType := range types {
				if extensionType != pskExtensionTypeName {
					continue
				}
				if i != len(types)-1 {
					t.Fatalf("pre_shared_key at index %d of %d, want last", i, len(types))
				}
			}
		})
	}
}

// TestResumptionRequiresPrerequisiteExtensions states the rule positively: a
// preset is eligible only when it already advertises the extensions a resumed
// handshake needs. Anything else keeps its stock fingerprint and skips
// resumption.
func TestResumptionRequiresPrerequisiteExtensions(t *testing.T) {
	for name, id := range namedFingerprints(t) {
		t.Run(name, func(t *testing.T) {
			stock := stockSpec(t, name, id)

			hasSessionTicket, hasPSKModes := false, false
			for _, extension := range stock.Extensions {
				switch extension.(type) {
				case *utls.PSKKeyExchangeModesExtension:
					hasPSKModes = true
				case utls.ISessionTicketExtension:
					hasSessionTicket = true
				}
			}

			_, ok := resumptionSpec(stock)
			if eligible := hasSessionTicket && hasPSKModes; ok && !eligible {
				t.Fatalf("resumption enabled without prerequisites (session_ticket=%v psk_key_exchange_modes=%v)",
					hasSessionTicket, hasPSKModes)
			}
		})
	}
}

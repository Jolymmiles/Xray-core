package hysteria

import (
	"bytes"
	"context"
	"io"
	"testing"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

var (
	hysteriaServerLinkSink *transport.Link
	hysteriaPolicySink     featurepolicy.Session
	hysteriaUserSink       *protocol.MemoryUser
)

// BenchmarkServerUDPIOSetup measures the per-session link the server hands to
// the dispatcher. It is allocated per session because the link outlives
// Server.Process; see server_link_lifetime_test.go.
func BenchmarkServerUDPIOSetup(b *testing.B) {
	source := bytes.NewReader(nil)
	b.ReportAllocs()
	for b.Loop() {
		hysteriaServerLinkSink = &transport.Link{
			Reader: &UDPReader{reader: source},
			Writer: &UDPWriter{writer: io.Discard, addr: "example.com:443"},
		}
	}
}

func BenchmarkAnonymousServerUser(b *testing.B) {
	b.Run("per-connection", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaUserSink = new(protocol.MemoryUser)
		}
	})
	b.Run("shared-immutable", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaUserSink = anonymousHysteriaUser
		}
	})
}

func TestServerPolicyCachePreservesNonzeroLevels(t *testing.T) {
	manager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{policyManager: manager, sessionPolicy: manager.ForLevel(0)}
	if got, want := server.policyForLevel(0), manager.ForLevel(0); got != want {
		t.Fatalf("level 0 policy = %+v, want %+v", got, want)
	}
	if got, want := server.policyForLevel(7), manager.ForLevel(7); got != want {
		t.Fatalf("level 7 policy = %+v, want %+v", got, want)
	}
}

func BenchmarkServerPolicyForLevelZero(b *testing.B) {
	manager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		b.Fatal(err)
	}
	server := &Server{policyManager: manager, sessionPolicy: manager.ForLevel(0)}
	b.Run("manager", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaPolicySink = manager.ForLevel(0)
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaPolicySink = server.policyForLevel(0)
		}
	})
}

func BenchmarkServerTCPIOSetup(b *testing.B) {
	readerSource := bytes.NewReader(nil)
	b.ReportAllocs()
	for b.Loop() {
		if err := writeTCPResponseOK(io.Discard); err != nil {
			b.Fatal(err)
		}
		hysteriaServerLinkSink = &transport.Link{Reader: buf.NewReader(readerSource), Writer: buf.NewWriter(io.Discard)}
	}
}

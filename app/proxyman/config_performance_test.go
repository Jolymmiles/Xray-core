package proxyman

import (
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestBuildSniffingRequestProtocolMask(t *testing.T) {
	request, err := BuildSniffingRequest(&SniffingConfig{
		DestinationOverride: []string{"http", "tls", "fakedns"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := session.SniffingOverrideHTTP | session.SniffingOverrideTLS
	if request.OverrideProtocolMask != want {
		t.Fatalf("OverrideProtocolMask = %08b, want %08b", request.OverrideProtocolMask, want)
	}
}

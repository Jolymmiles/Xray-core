package internet_test

import (
	"testing"

	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// Mask settings arrive from configuration files and the HandlerService API,
// so a bad entry must fail the build of the stream settings, not the process.
func TestToMemoryStreamConfigRejectsInvalidMasks(t *testing.T) {
	unknown := &serial.TypedMessage{Type: "xray.test.UnknownMask"}
	tcpOnly := serial.ToTypedMessage(&fragment.Config{})
	for _, test := range []struct {
		name   string
		config *StreamConfig
	}{
		{"unknown TCP mask", &StreamConfig{Tcpmasks: []*serial.TypedMessage{unknown}}},
		{"unknown UDP mask", &StreamConfig{Udpmasks: []*serial.TypedMessage{unknown}}},
		{"TCP mask in UDP list", &StreamConfig{Udpmasks: []*serial.TypedMessage{tcpOnly}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("ToMemoryStreamConfig panicked: %v", recovered)
				}
			}()
			_, err := ToMemoryStreamConfig(test.config)
			if err == nil {
				t.Fatal("ToMemoryStreamConfig accepted an invalid mask")
			}
			t.Logf("rejected: %v", err)
		})
	}
}

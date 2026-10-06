package splithttp

import (
	"context"
	"fmt"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// TestFlowOffLeavesStockWiring (added for bdbac60e) checks the default: with
// XRAY_XHTTP_FLOW unset and no "h2Flow", ListenXH does not wrap its listener,
// net/http gets Go's HTTP/2 windows, and the client transport is Go's.
func TestFlowOffLeavesStockWiring(t *testing.T) {
	if flowEnabled {
		t.Skip("XRAY_XHTTP_FLOW=on in the environment")
	}
	for _, tc := range []struct {
		flow    *H2FlowConfig
		wrapped bool
	}{{nil, false}, {&H2FlowConfig{Mode: 2}, false}, {&H2FlowConfig{Mode: 1}, true}} {
		t.Run(fmt.Sprintf("%v", tc.flow), func(t *testing.T) {
			cfg := &Config{Path: "shs", H2Flow: tc.flow}
			port := tcp.PickPort()
			ln, err := ListenXH(context.Background(), xnet.LocalHostIP, port, &internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: cfg}, func(stat.Connection) {})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			l := ln.(*Listener)
			_, wrapped := l.listener.(*flowListener)
			if wrapped != tc.wrapped {
				t.Fatalf("listener wrapped %v, want %v", wrapped, tc.wrapped)
			}
			if !tc.wrapped && l.server.HTTP2 != nil {
				t.Fatalf("ungoverned server HTTP2 config %+v, want Go's defaults", l.server.HTTP2)
			}
			if !tc.wrapped && cfg.h2ReceiveConfig(false) != nil {
				t.Fatal("ungoverned client gets a non-default HTTP/2 config")
			}
		})
	}
}

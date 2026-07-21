package dispatcher

import (
	"context"
	"runtime/debug"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	dns_proto "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
)

func TestDispatchLinkCachedReaderSurvivesOutboundDispatch(t *testing.T) {
	handler := new(captureOutbound)
	dispatcher := newPerformanceDispatcher(handler)
	ctx := context.WithValue(performanceContext(), core.XrayKey(1), &core.Instance{})
	content := session.ContentFromContext(ctx)
	content.SniffingRequest.Enabled = true
	content.SniffingRequest.MetadataOnly = true

	link := &transport.Link{
		Reader: &singleBufferTimeoutReader{payload: []byte("dns request")},
		Writer: buf.Discard,
	}
	if err := dispatcher.DispatchLink(ctx, net.UDPDestination(net.DomainAddress("dns.example"), 53), link); err != nil {
		t.Fatal(err)
	}

	reader := &dns_proto.UDPReader{Reader: handler.reader}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("late DNS read panicked after outbound Dispatch returned: %v\n%s", recovered, debug.Stack())
		}
	}()

	message, err := reader.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	message.Release()
}

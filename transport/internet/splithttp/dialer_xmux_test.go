package splithttp

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// a dial reserves the XMUX client it picks before it lets go of the dialer
// map, so with "maxConcurrency" 1 the next dial picks another client even when
// both pick before either is set up
func TestDialReservesItsXmuxClient(t *testing.T) {
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{}}
	dest := net.TCPDestination(net.DomainAddress("xhttp.invalid"), 443)

	globalDialerAccess.Lock()
	previous := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{dest, settings}: NewXmuxManager(&XmuxConfig{MaxConcurrency: &RangeConfig{From: 1, To: 1}}, func() XmuxConn { return &DefaultDialerClient{} }),
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = previous
		globalDialerAccess.Unlock()
	})

	_, first := getHTTPClient(context.Background(), dest, settings)
	_, second := getHTTPClient(context.Background(), dest, settings)
	if first == second {
		t.Fatalf("two dials took one client with maxConcurrency 1 (running %d)", first.Running.Load())
	}
	for _, client := range []*XmuxClient{first, second} {
		if n := client.Running.Load(); n != 1 {
			t.Errorf("a client picked by one dial has %d running, want 1", n)
		}
	}
}

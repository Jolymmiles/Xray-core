package splithttp

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// The governor wraps the accepted connection; the client's physical address
// captured beneath it must stay visible through the wrapper.
func TestFlowConnKeepsPhysicalPeer(t *testing.T) {
	a, b := gonet.Pipe()
	defer a.Close()
	defer b.Close()
	peer := &gonet.TCPAddr{IP: gonet.ParseIP("203.0.113.7"), Port: 4242}
	fc := newFlowConn(net.WithPhysicalPeer(peer, a), flowDefault, flowDefault)
	got, ok := net.PhysicalPeer(fc)
	if !ok || got.String() != peer.String() {
		t.Fatalf("physical peer through the governor: %v, %v; want %v", got, ok, peer)
	}
}

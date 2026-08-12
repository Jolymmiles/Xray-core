package stat

import (
	"net"
	"testing"
	"time"

	corenet "github.com/xtls/xray-core/common/net"
)

type unwrapTestConn struct{}

func (*unwrapTestConn) Read([]byte) (int, error)         { return 0, nil }
func (*unwrapTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*unwrapTestConn) Close() error                     { return nil }
func (*unwrapTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*unwrapTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.ParseIP("192.0.2.1")} }
func (*unwrapTestConn) SetDeadline(time.Time) error      { return nil }
func (*unwrapTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*unwrapTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestTryUnwrapStatsConnTreatsPhysicalPeerAsTransparent(t *testing.T) {
	raw := &unwrapTestConn{}
	wrapped := &CounterConnection{Connection: corenet.CapturePhysicalPeer(raw)}
	if got := TryUnwrapStatsConn(wrapped); got != raw {
		t.Fatalf("TryUnwrapStatsConn() = %T, want raw connection", got)
	}
}

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

type closeWriteTrackingConn struct {
	net.Conn
	calls int
}

func (c *closeWriteTrackingConn) CloseWrite() error {
	c.calls++
	return nil
}

func TestTryCloseWriteUnwrapsCounterConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	tracked := &closeWriteTrackingConn{Conn: client}
	wrapped := &CounterConnection{Connection: tracked}
	if err := TryCloseWrite(wrapped); err != nil {
		t.Fatal(err)
	}
	if tracked.calls != 1 {
		t.Fatalf("CloseWrite calls = %d, want 1", tracked.calls)
	}
}

type rawOnlyCloseWriteConn struct {
	net.Conn
	raw net.Conn
}

func (c *rawOnlyCloseWriteConn) Raw() net.Conn { return c.raw }

func TestTryCloseWriteUsesPhysicalPeerAdapterBeforeUnwrap(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	tracked := &closeWriteTrackingConn{Conn: client}
	rawOnly := &rawOnlyCloseWriteConn{Conn: client, raw: tracked}
	wrapped := corenet.WithPhysicalPeer(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}, rawOnly)
	if err := TryCloseWrite(wrapped); err != nil {
		t.Fatal(err)
	}
	if tracked.calls != 1 {
		t.Fatalf("CloseWrite calls = %d, want 1", tracked.calls)
	}
}

func TestTryCloseWriteIgnoresUnsupportedConnection(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	if err := TryCloseWrite(client); err != nil {
		t.Fatal(err)
	}
}

package splithttp

import (
	"io"
	"testing"
	"testing/synctest"
	"time"
)

type discardWriteCloser struct{}

func (discardWriteCloser) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriteCloser) Close() error                { return nil }

// A Mux.Cool KeepAlive waits on DownlinkIdle: it grows while the downlink is
// silent and starts over with every write.
func TestSplitConnDownlinkIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &splitConn{writer: discardWriteCloser{}, reader: io.NopCloser(nil)}
		conn.markWritten()
		time.Sleep(3 * time.Second)
		if idle := conn.DownlinkIdle(); idle != 3*time.Second {
			t.Fatalf("idle %v after 3s of silence, want 3s", idle)
		}
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if idle := conn.DownlinkIdle(); idle != 0 {
			t.Fatalf("idle %v right after a write, want 0", idle)
		}
	})
}

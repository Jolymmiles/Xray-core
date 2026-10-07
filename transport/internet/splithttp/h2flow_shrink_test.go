package splithttp

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlowWindowShrinks reads fast until the window has grown, then slowly, as
// a video player does once its buffer is full: the window must come back
// down instead of keeping a slow reader's unread data at the fast size.
func TestFlowWindowShrinks(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for _, role := range []string{"server", "client"} {
		up, down := testUp, testDown
		if role == "client" {
			up, down = flowLimit{}, flowLimit{}
		}
		tl, addr := startFlowServer(t, up, down, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 16<<10)
			for {
				if _, err := w.Write(buf); err != nil {
					return
				}
			}
		}))
		proxy := lagProxy(t, addr, 20*time.Millisecond)
		var get func(string) (*http.Response, error)
		var client *flowClient
		if role == "client" {
			client = newFlowTestClient(proxy, true)
			get = client.Get
		} else {
			get = h2Client(proxy).Get
		}
		resp, err := get("http://x/down")
		if err != nil {
			t.Fatal(err)
		}
		state := func() (unread int64, cap int32) {
			f := func(c *flowConn) {
				for _, s := range c.streams {
					unread, cap = max(unread, s.downSent-s.down.returned), max(cap, s.down.cap)
				}
			}
			if client != nil {
				client.each(f)
			} else {
				tl.each(f)
			}
			return
		}
		deadline := time.Now().Add(2 * time.Second)
		buf := make([]byte, 64<<10)
		for time.Now().Before(deadline) {
			if _, err := resp.Body.Read(buf); err != nil {
				t.Fatal(err)
			}
		}
		fastUnread, fastCap := state()
		var consumed atomic.Int64
		stop := make(chan struct{})
		go slowCopy(resp.Body, 1<<20, &consumed, stop)
		time.Sleep(8 * time.Second)
		slowUnread, slowCap := state()
		close(stop)
		resp.Body.Close()
		t.Logf("%s: after the fast phase cap %d unread %d; after the slow phase cap %d unread %d", role, fastCap, fastUnread, slowCap, slowUnread)
		if fastCap < 1<<20 {
			t.Fatalf("%s: the window did not grow in the fast phase (%d)", role, fastCap)
		}
		if slowCap > 256<<10 || slowUnread > 256<<10 {
			t.Fatalf("%s: the window stayed at %d with %d unread after slowing down", role, slowCap, slowUnread)
		}
	}
}

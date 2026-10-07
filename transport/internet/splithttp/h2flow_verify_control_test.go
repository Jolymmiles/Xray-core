package splithttp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// governorPing opens stream 1 and returns the payload of the PING the
// governor then sends the client.
func governorPing(t *testing.T, h *flowHarness) [8]byte {
	t.Helper()
	h.dueForPing()
	ps := pings(t, h.fromServer(func(fr *http2.Framer) { fr.WriteData(1, false, make([]byte, 10)) }))
	if len(ps) != 1 {
		t.Fatalf("governor sent %d PINGs at a due frame boundary, want 1", len(ps))
	}
	return ps[0]
}

// TestFlowControlFramesInHeaderBlockPassVerbatim puts control frames the
// governor would otherwise rewrite or swallow between a HEADERS frame without
// END_HEADERS and its CONTINUATION. Stock HTTP/2 rejects any such frame, so
// the governor must hand the whole sequence on unchanged for the server's
// framer to fail it.
func TestFlowControlFramesInHeaderBlockPassVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner func(fr *http2.Framer, ours [8]byte)
	}{
		{"governor PING ACK", func(fr *http2.Framer, ours [8]byte) { fr.WritePing(true, ours) }},
		// The stream has handed back credit once already, so the governor
		// would answer this one with a larger, rewritten increment.
		{"WINDOW_UPDATE", func(fr *http2.Framer, _ [8]byte) { fr.WriteWindowUpdate(1, 1<<20) }},
		{"SETTINGS", func(fr *http2.Framer, _ [8]byte) {
			fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFlowHarness(t)
			h.openStream(4 << 20)
			ours := governorPing(t, h)
			h.fromClient(func(fr *http2.Framer) { fr.WriteWindowUpdate(1, 10) })
			in := frames(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x82}})
				tc.inner(fr, ours)
				fr.WriteContinuation(3, true, []byte{0x84})
			})
			got := h.fromClientRaw(in)
			if !bytes.HasPrefix(got, in) {
				t.Fatalf("server read\n%x\nclient sent\n%x", got, in)
			}
			fr := http2.NewFramer(nil, bytes.NewReader(got))
			if _, err := fr.ReadFrame(); err != nil {
				t.Fatal(err)
			}
			var ce http2.ConnectionError
			if _, err := fr.ReadFrame(); !errors.As(err, &ce) || http2.ErrCode(ce) != http2.ErrCodeProtocol {
				t.Fatalf("stock framer read %v after HEADERS, want PROTOCOL_ERROR", err)
			}
		})
	}
}

// TestFlowPingAckOnStreamPassesVerbatim answers the governor's PING with an
// ACK on stream 1, which stock HTTP/2 rejects: it is not the governor's.
func TestFlowPingAckOnStreamPassesVerbatim(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	ours := governorPing(t, h)
	in := frames(func(fr *http2.Framer) { fr.WriteRawFrame(http2.FramePing, http2.FlagPingAck, 1, ours[:]) })
	if got := h.fromClientRaw(in); !bytes.HasPrefix(got, in) {
		t.Fatalf("server read %x, client sent %x", got, in)
	}
}

// TestFlowNoInjectionInsidePushPromise has the server start a PUSH_PROMISE
// header block while a governor PING is due. Nothing may reach the client
// between that frame and its CONTINUATION.
func TestFlowNoInjectionInsidePushPromise(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	h.dueForPing()
	h.conn.take() // credit for stream 1, sent before the header block
	in := frames(func(fr *http2.Framer) {
		fr.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: []byte{0x82}})
	})
	got, err := h.fromServerRaw(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("client read %x inside a header block, server sent %x", got, in)
	}
}

// TestFlowPingPayloadIsUnpredictable checks that a TLS-terminating observer
// cannot tell the governor's PINGs by their payload, and that the governor
// still recognises exactly its own ACKs.
func TestFlowPingPayloadIsUnpredictable(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	var seen [][8]byte
	for range 3 {
		p := governorPing(t, h)
		if string(p[:4]) == "xflw" {
			t.Fatalf("PING payload %x carries the governor's fixed tag", p)
		}
		for _, q := range seen {
			if bytes.Equal(p[:4], q[:4]) {
				t.Fatalf("PING payloads %x and %x share a fixed prefix", q, p)
			}
		}
		seen = append(seen, p)

		forged := p
		forged[7] ^= 1
		ack := frames(func(fr *http2.Framer) { fr.WritePing(true, p) })
		other := frames(func(fr *http2.Framer) { fr.WritePing(true, forged) })
		got := h.fromClientRaw(append(append([]byte(nil), other...), ack...))
		if !bytes.Contains(got, other) {
			t.Fatal("an ACK that is not the governor's did not reach the server")
		}
		if bytes.Contains(got, ack) {
			t.Fatal("the governor passed on the ACK of its own PING")
		}
	}
}

// TestFlowRecognisesEveryOutstandingPing keeps a periodic PING and a guard
// probe in flight together: the ACK of each is the governor's own.
func TestFlowRecognisesEveryOutstandingPing(t *testing.T) {
	h := newFlowHarness(t)
	h.openStream(4 << 20)
	periodic := governorPing(t, h)
	// The guard probes only while a stream waits for credit (item E).
	h.c.mu.Lock()
	h.c.streams[1].down.waiting = time.Now()
	h.c.mu.Unlock()
	h.c.fireGuard()
	h.sync()
	probes := pings(t, h.conn.take())
	if len(probes) != 1 {
		t.Fatalf("guard sent %d PINGs, want 1", len(probes))
	}
	for _, p := range [][8]byte{periodic, probes[0]} {
		ack := frames(func(fr *http2.Framer) { fr.WritePing(true, p) })
		if got := h.fromClientRaw(ack); bytes.Contains(got, ack) {
			t.Fatalf("the governor did not recognise the ACK of its PING %x", p)
		}
	}
}

// TestFlowForgetsOldestPings is not transplanted: it tests flowPingSlots, a
// mechanism of the pr17-fixes branch that bdbac60e does not have.

// pingReaction connects to a server, answers the first PING it sends (or uses
// a fixed payload when it sends none) with the frames build returns, and
// reports how the server reacts, as h2Reaction does.
func pingReaction(t *testing.T, addr string, build func(ping [8]byte) []byte) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(append([]byte(h2Preface), frames(func(fr *http2.Framer) { fr.WriteSettings() })...))
	fr := http2.NewFramer(nil, conn)
	ping := [8]byte{'n', 'o', 'n', 'e'}
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if p, ok := f.(*http2.PingFrame); ok && !p.IsAck() {
			ping = p.Data
			break
		}
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write(build(ping))
	goaway := "none"
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			end := "closed"
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				end = "left open"
			}
			return fmt.Sprintf("goaway %s, connection %s", goaway, end)
		}
		if g, ok := f.(*http2.GoAwayFrame); ok {
			goaway = g.ErrCode.String()
		}
	}
}

// TestFlowPingViolationsGetStockErrors (added for bdbac60e) answers the
// governor's PING with an ACK that stock HTTP/2 rejects, on a stock and a
// governed server: on stream 1, and between HEADERS and its CONTINUATION.
func TestFlowPingViolationsGetStockErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, stock := startFlowServer(t, flowLimit{}, flowLimit{}, false, handler)
	_, governed := startFlowServer(t, testUp, testDown, false, handler)
	for _, tc := range []struct {
		name  string
		build func(ping [8]byte) []byte
	}{
		{"PING ACK on stream 1", func(p [8]byte) []byte {
			return frames(func(fr *http2.Framer) { fr.WriteRawFrame(http2.FramePing, http2.FlagPingAck, 1, p[:]) })
		}},
		{"PING ACK inside a header block", func(p [8]byte) []byte {
			return frames(func(fr *http2.Framer) {
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}})
				fr.WritePing(true, p)
				fr.WriteContinuation(1, true, []byte{0x86, 0x84, 0x01, 0x01, 'x'})
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := pingReaction(t, stock, tc.build)
			got := pingReaction(t, governed, tc.build)
			t.Logf("stock: %s; governed: %s", want, got)
			if got != want {
				t.Fatalf("governed server: %s; stock: %s", got, want)
			}
		})
	}
}

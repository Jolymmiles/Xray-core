package splithttp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// writeDataSplit writes n bytes of DATA on stream id in default-size frames.
func writeDataSplit(fr *http2.Framer, id uint32, n int) {
	for n > 0 {
		m := min(n, h2MinMaxFrameSize)
		fr.WriteData(id, false, make([]byte, m))
		n -= m
	}
}

// TestFlowInitialWindowDecrease lowers the client's initial window after the
// governor has handed the server credit beyond the window it shows. The real
// window of the stream drops with it, so what the server may still send has
// to drop as far; when no SETTINGS value can take it that far, the governor
// must give up the connection instead of letting the server overrun the
// client.
func TestFlowInitialWindowDecrease(t *testing.T) {
	const sent = 32 << 10
	for _, tc := range []struct {
		lowered    uint32
		expressive bool
	}{
		{200000, true},
		{0, false},
	} {
		t.Run(fmt.Sprintf("to %d", tc.lowered), func(t *testing.T) {
			h := newFlowHarness(t)
			h.track()
			h.openStream(4 << 20)
			if got := h.toServer.streams[1]; got != flowStartWindow {
				t.Fatalf("server opened stream 1 with %d of credit, want %d", got, flowStartWindow)
			}
			h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, sent) })
			h.toServer.streams[1] -= sent

			h.fromClient(func(fr *http2.Framer) {
				fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: tc.lowered})
			})
			real := int64(tc.lowered) - sent
			if !tc.expressive {
				if h.readErr == nil || !h.conn.isClosed() {
					t.Fatalf("server may still send %d on stream 1 while the client allows %d, and the connection is still up (read error %v)",
						h.toServer.streams[1], real, h.readErr)
				}
				if _, err := h.fromServerRaw(frames(func(fr *http2.Framer) { fr.WriteData(1, false, make([]byte, 100)) })); err == nil {
					t.Fatal("the server could still send after the governor gave up the connection")
				}
				return
			}
			if h.readErr != nil {
				t.Fatalf("governor failed a change it can express: %v", h.readErr)
			}
			if view := h.toServer.streams[1]; view > real {
				t.Fatalf("server may still send %d on stream 1 while the client allows %d", view, real)
			}
		})
	}
}

// TestFlowInitialWindowIncrease raises the client's initial window after the
// server used up the default one. The client then counts on the server
// having room and owes no credit, so the governor has to hand the server its
// share of the new window, after the SETTINGS frame that funds it.
func TestFlowInitialWindowIncrease(t *testing.T) {
	h := newFlowHarness(t)
	h.track()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	})
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	h.fromServer(func(fr *http2.Framer) { writeDataSplit(fr, 1, h2InitWindow) })
	h.toServer.streams[1] -= h2InitWindow
	if view := h.toServer.streams[1]; view != 0 {
		t.Fatalf("server has %d left on stream 1 after using the default window", view)
	}

	before := len(h.toServer.frames)
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	real := int64(4<<20) - h2InitWindow
	view := h.toServer.streams[1]
	if view <= 0 {
		t.Fatalf("stream 1 stalls: the server has %d of credit while the client allows %d and owes none", view, real)
	}
	if view > real {
		t.Fatalf("server may send %d on stream 1 while the client allows %d", view, real)
	}
	settingsAt, creditAt := -1, -1
	for i, frame := range h.toServer.frames[before:] {
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if settingsAt < 0 {
				settingsAt = i
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 1 && creditAt < 0 {
				creditAt = i
			}
		}
	}
	if settingsAt < 0 || creditAt < settingsAt {
		t.Fatalf("credit for stream 1 at frame %d reaches the server before the SETTINGS that funds it at %d", creditAt, settingsAt)
	}
}

// TestFlowInitialWindowChangeOrdering lets the governor grant upload credit
// to a new stream while the server is half way through a SETTINGS frame that
// lowers its window. The credit waits behind that frame, so the client
// applies the lower window first and the credit after it; together they must
// not exceed what the server really accepts.
func TestFlowInitialWindowChangeOrdering(t *testing.T) {
	const lowered = 200000
	h := newFlowHarness(t)
	h.track()
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20})
	})
	h.fromServer(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	})

	lower := frames(func(fr *http2.Framer) {
		fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: lowered})
	})
	if _, err := h.fromServerRaw(lower[:5]); err != nil {
		t.Fatal(err)
	}
	h.toClient.open(1)
	h.fromClient(func(fr *http2.Framer) {
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}, EndHeaders: true})
	})
	if _, err := h.fromServerRaw(lower[5:]); err != nil {
		t.Fatal(err)
	}
	if view := h.toClient.streams[1]; view > lowered {
		t.Fatalf("client may send %d on stream 1 while the server accepts %d", view, lowered)
	}
	if view := h.toClient.streams[1]; view <= 0 {
		t.Fatalf("client has %d of credit on stream 1 while the server accepts %d", view, lowered)
	}
}

func settingsPayload(entries ...[2]uint32) []byte {
	var p []byte
	for _, e := range entries {
		p = binary.BigEndian.AppendUint16(p, uint16(e[0]))
		p = binary.BigEndian.AppendUint32(p, e[1])
	}
	return p
}

var malformedSettings = []struct {
	name   string
	stream uint32
	values [][2]uint32
}{
	{"initial window above 2^31-1", 0, [][2]uint32{{h2SettingInitialWindowSize, 0x80000000}}},
	{"max frame size above 2^24-1", 0, [][2]uint32{{h2SettingMaxFrameSize, 0x01000000}}},
	{"invalid ENABLE_PUSH beside a window", 0, [][2]uint32{{h2SettingInitialWindowSize, 4 << 20}, {0x2, 2}}},
	{"SETTINGS on a stream", 1, [][2]uint32{{h2SettingInitialWindowSize, 4 << 20}, {h2SettingMaxFrameSize, 1 << 20}}},
}

// TestFlowMalformedSettingsPassVerbatim sends SETTINGS that stock HTTP/2
// rejects in both directions: the governor must hand them on byte for byte,
// so the receiving stack fails them as it would without the governor.
func TestFlowMalformedSettingsPassVerbatim(t *testing.T) {
	for _, tc := range malformedSettings {
		in := frames(func(fr *http2.Framer) {
			fr.WriteRawFrame(http2.FrameSettings, 0, tc.stream, settingsPayload(tc.values...))
		})
		t.Run("client "+tc.name, func(t *testing.T) {
			h := newFlowHarness(t)
			if got := h.fromClientRaw(in); !bytes.Equal(got, in) {
				t.Fatalf("server read %x, client sent %x", got, in)
			}
		})
		t.Run("server "+tc.name, func(t *testing.T) {
			h := newFlowHarness(t)
			got, err := h.fromServerRaw(in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, in) {
				t.Fatalf("client read %x, server sent %x", got, in)
			}
		})
	}
}

// An oversized SETTINGS frame passes on as it is: net/http rejects more than
// 100 settings in one frame, so the real window inside it never takes effect,
// and the peer sees the stock GOAWAY (TestFlowOversizedSettingsGetStockErrors).
// Failing the connection in the governor instead would change that answer.

// h2Reaction sends the preface and frames to a server and reports whether it
// acknowledged the client's SETTINGS, which GOAWAY code it sent, and whether
// it closed the connection or left it open.
func h2Reaction(t *testing.T, addr string, in []byte) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(append([]byte(h2Preface), in...)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(nil, conn)
	acked, goaway := false, "none"
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			end := "closed"
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				end = "left open"
			}
			return fmt.Sprintf("settings acked %v, goaway %s, connection %s", acked, goaway, end)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			acked = acked || f.IsAck()
		case *http2.GoAwayFrame:
			goaway = f.ErrCode.String()
		}
	}
}

// TestFlowMalformedSettingsGetStockErrors sends the same malformed SETTINGS
// to a stock and a governed server and expects the same answer.
func TestFlowMalformedSettingsGetStockErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, stock := startFlowServer(t, flowLimit{}, flowLimit{}, false, handler)
	_, governed := startFlowServer(t, testUp, testDown, false, handler)
	for _, tc := range malformedSettings {
		t.Run(tc.name, func(t *testing.T) {
			in := frames(func(fr *http2.Framer) {
				fr.WriteRawFrame(http2.FrameSettings, 0, tc.stream, settingsPayload(tc.values...))
			})
			want := h2Reaction(t, stock, in)
			if got := h2Reaction(t, governed, in); got != want {
				t.Fatalf("governed server: %s; stock: %s", got, want)
			}
		})
	}
}

// TestFlowOversizedSettingsGetStockErrors (added for bdbac60e) sends the
// oversized SETTINGS of TestFlowOversizedSettingsFailClosed to a stock and a
// governed server: net/http rejects more than 100 settings itself, so the
// governor's pass-through does not change what a peer observes.
func TestFlowOversizedSettingsGetStockErrors(t *testing.T) {
	values := make([][2]uint32, h2MinMaxFrameSize/6)
	for i := range values {
		values[i] = [2]uint32{0x1, 4096}
	}
	values = append(values, [2]uint32{h2SettingInitialWindowSize, 4 << 20})
	in := frames(func(fr *http2.Framer) {
		fr.WriteRawFrame(http2.FrameSettings, 0, 0, settingsPayload(values...))
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, stock := startFlowServer(t, flowLimit{}, flowLimit{}, false, handler)
	_, governed := startFlowServer(t, testUp, testDown, false, handler)
	want := h2Reaction(t, stock, in)
	got := h2Reaction(t, governed, in)
	t.Logf("stock: %s; governed: %s", want, got)
	if got != want {
		t.Fatalf("governed server: %s; stock: %s", got, want)
	}
}

package salamander

import (
	"net"
	"strings"
	"testing"
	"time"
)

var geckoTestAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345}

func newGeckoReassembler() *geckoConn {
	return &geckoConn{reassembly: make(map[reassemblyKey]*reassemblyEntry), perSource: make(map[string]int)}
}

type geckoFragment struct {
	index uint8
	data  string
}

// Gecko's message ID is one byte and repeats every 256 fragmented messages,
// and no field ties a fragment to its message. When message A lost a
// fragment, message B under the same ID must not complete A's entry, nor may
// a delayed tail of A complete B: the receiver may deliver A or B whole, or
// nothing, but never a mix. A transport without its own integrity check
// (mKCP without a mask) would pass a mix into the stream.
func TestGeckoDoesNotDeliverSplicedMessage(t *testing.T) {
	const a, b = "A0A0A1A1A2A2", "B0B0B1B1B2B2"
	for _, tc := range []struct {
		name      string
		fragments []geckoFragment
	}{
		{"B fills A's gap", []geckoFragment{{0, "A0A0"}, {2, "A2A2"}, {0, "B0B0"}, {1, "B1B1"}, {2, "B2B2"}}},
		{"A's delayed tail meets B", []geckoFragment{{0, "A0A0"}, {2, "A2A2"}, {0, "B0B0"}, {1, "A1A1"}, {2, "B2B2"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGeckoReassembler()
			for _, f := range tc.fragments {
				out, ready := g.acceptChunk(geckoTestAddr, frameHeader{msgID: 7, chunkIdx: f.index, totalChunks: 3}, []byte(f.data))
				if ready && string(out) != a && string(out) != b {
					t.Fatalf("delivered a packet spliced from two messages: %q", out)
				}
			}
		})
	}
}

// A chunk that cannot belong to the message an entry holds quarantines the
// ID until the entry's original deadline; the next message after it
// reassembles normally, and the quarantine stays within the entry caps.
func TestGeckoQuarantinesConflictingChunks(t *testing.T) {
	start := time.Unix(1000, 0)
	for _, tc := range []struct {
		name     string
		conflict geckoFragment
		total    uint8
	}{
		{"different bytes at a repeated index", geckoFragment{0, "bbbb"}, 3},
		{"non-last chunk of another length", geckoFragment{1, "bbbbb"}, 3},
		{"last chunk shorter than the others", geckoFragment{2, "bb"}, 3},
		{"different chunk count", geckoFragment{1, "bbbb"}, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGeckoReassembler()
			send := func(f geckoFragment, total uint8, now time.Time) ([]byte, bool) {
				return g.acceptChunkAt(geckoTestAddr, frameHeader{msgID: 7, chunkIdx: f.index, totalChunks: total}, []byte(f.data), now)
			}
			send(geckoFragment{0, "aaaa"}, 3, start)
			send(tc.conflict, tc.total, start)
			e := g.reassembly[reassemblyKey{addr: geckoTestAddr.String(), msgID: 7}]
			if e == nil || !e.poisoned || e.chunks != nil {
				t.Fatal("the conflict did not quarantine the ID and release its chunks")
			}
			for i := range uint8(3) {
				if out, ok := send(geckoFragment{i, "BBBB"}, 3, start.Add(geckoReassemblyTTL)); ok {
					t.Fatalf("a quarantined ID delivered %q", out)
				}
			}
			if len(g.reassembly) != 1 || g.perSource[geckoTestAddr.String()] != 1 {
				t.Fatalf("quarantine holds %d entries, %d for the source; want 1 and 1", len(g.reassembly), g.perSource[geckoTestAddr.String()])
			}
			after := start.Add(geckoReassemblyTTL + time.Nanosecond)
			var out []byte
			var ok bool
			for i := range uint8(3) {
				out, ok = send(geckoFragment{i, "CCCC"}, 3, after)
			}
			if !ok || string(out) != "CCCCCCCCCCCC" {
				t.Fatalf("after the quarantine expired: delivered %q, %v; want the next message", out, ok)
			}
		})
	}
}

// The checks must not drop a legitimate message: chunks split the way every
// Gecko sender splits them, received in reverse with exact duplicates,
// reassemble once, including messages shorter than their chunk count.
func TestGeckoReassemblesReorderedDuplicatedMessages(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, message := range []string{"\x80", "\x80hello world!", "\x80" + strings.Repeat("a", 1200)} {
		for chunks := geckoMinFragmentChunks; chunks <= geckoMaxFragmentChunks; chunks++ {
			g := newGeckoReassembler()
			size := len(message) / chunks
			delivered := 0
			var got []byte
			for i := chunks - 1; i >= 0; i-- {
				end := len(message)
				if i < chunks-1 {
					end = (i + 1) * size
				}
				h := frameHeader{msgID: 7, chunkIdx: uint8(i), totalChunks: uint8(chunks)}
				for range 2 {
					if out, ok := g.acceptChunkAt(geckoTestAddr, h, []byte(message[i*size:end]), now); ok {
						delivered++
						got = out
					}
				}
			}
			if delivered != 1 || string(got) != message {
				t.Fatalf("%d-byte message in %d chunks: delivered %d times, last %q", len(message), chunks, delivered, got)
			}
		}
	}
}

// An expired entry the collector has not reached yet must not absorb the
// chunks of a newer message under the same ID.
func TestGeckoExpiredEntryDoesNotAbsorbNewMessage(t *testing.T) {
	g := newGeckoReassembler()
	start := time.Unix(1000, 0)
	g.acceptChunkAt(geckoTestAddr, frameHeader{msgID: 7, chunkIdx: 0, totalChunks: 2}, []byte("A0"), start)
	later := start.Add(geckoReassemblyTTL + time.Second)
	if out, ok := g.acceptChunkAt(geckoTestAddr, frameHeader{msgID: 7, chunkIdx: 1, totalChunks: 2}, []byte("B1"), later); ok {
		t.Fatalf("an expired entry completed with a newer chunk: %q", out)
	}
	if out, ok := g.acceptChunkAt(geckoTestAddr, frameHeader{msgID: 7, chunkIdx: 0, totalChunks: 2}, []byte("B0"), later); !ok || string(out) != "B0B1" {
		t.Fatalf("delivered %q, %v; want the newer message %q", out, ok, "B0B1")
	}
}

// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// TestSessionOwnershipUnderConcurrentTeardown hammers the paths that decide who
// owns a receive buffer: enqueue, both read APIs, the receive-stall abort, local
// close, and session teardown mid-flight.
//
// Every buffer here is pool-managed, so a buffer released twice or read after
// release lands in memory the pool has already handed to someone else. Run under
// -race and -gcflags=all=-d=checkptr=2, which is where such a handoff shows up.
func TestSessionOwnershipUnderConcurrentTeardown(t *testing.T) {
	const (
		streams = 24
		frames  = 12
		payload = 4096
	)

	client, server := testSessionPair(t, func(config *Config) {
		// Force backpressure and stalls rather than the happy path: one frame
		// per write, a two-frame stream window, and a session-wide receive
		// budget far smaller than the streams could collectively queue.
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * 2
		config.MaxReceiveBuffer = payload * 16
		config.StreamStallTimeout = 15 * time.Millisecond
	})

	body := make([]byte, payload)
	for i := range body {
		body[i] = byte(i)
	}

	var written, read, opened atomic.Int64
	// Guards against a branch silently going unreachable and the test passing
	// while exercising nothing.
	var roles [4]atomic.Int64

	var handlers sync.WaitGroup
	var accepting sync.WaitGroup
	accepting.Go(func() {
		for {
			stream, err := server.AcceptStream()
			if err != nil {
				return
			}
			// Round-robin on accept order, not on stream.ID: a client only ever
			// allocates odd identifiers, so keying on the ID leaves half the
			// branches below unreachable.
			role := opened.Add(1) % 4
			handlers.Go(func() {
				// Mix both read APIs and both teardown paths, so a frame can be
				// in flight while its stream is being torn down.
				roles[role].Add(1)
				switch role {
				case 0:
					read.Add(readWithMultiBuffer(stream))
				case 1:
					read.Add(readWithByteSlice(stream))
				case 2:
					// Leave data unread so the sender fills the window and the
					// carrier hits the stall timeout, then abort mid-flight.
					time.Sleep(20 * time.Millisecond)
					_ = stream.Abort()
				default:
					time.Sleep(5 * time.Millisecond)
					_ = stream.Close()
				}
			})
		}
	})

	var writers sync.WaitGroup
	for range streams {
		writers.Go(func() {
			stream, err := client.OpenStream()
			if err != nil {
				return
			}
			defer stream.Close()
			_ = stream.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			for range frames {
				n, err := stream.Write(body)
				written.Add(int64(n))
				if err != nil {
					// Expected: the peer aborts or closes mid-stream.
					return
				}
			}
		})
	}
	writers.Wait()

	// Tear the session down while reads, aborts and closes are still resolving.
	_ = client.Close()
	_ = server.Close()
	accepting.Wait()
	handlers.Wait()

	t.Logf("opened=%d written=%d read=%d roles=%d/%d/%d/%d", opened.Load(),
		written.Load(), read.Load(), roles[0].Load(), roles[1].Load(),
		roles[2].Load(), roles[3].Load())

	if got := opened.Load(); got != streams {
		t.Fatalf("accepted %d streams, want %d", got, streams)
	}
	for role := range roles {
		if roles[role].Load() == 0 {
			t.Fatalf("role %d never ran: the stress test is not exercising it", role)
		}
	}
	if written.Load() == 0 || read.Load() == 0 {
		t.Fatalf("no traffic moved: written=%d read=%d", written.Load(), read.Load())
	}
}

func readWithMultiBuffer(stream *Stream) int64 {
	var total int64
	for {
		mb, err := stream.ReadMultiBuffer()
		if err != nil {
			return total
		}
		total += int64(mb.Len())
		// The pipeline's contract: consume, then release exactly once.
		for _, b := range mb {
			_ = b.Bytes()
		}
		buf.ReleaseMulti(mb)
	}
}

func readWithByteSlice(stream *Stream) int64 {
	var total int64
	sink := make([]byte, 1000) // smaller than a frame, so chunks are read partially
	for {
		n, err := stream.Read(sink)
		total += int64(n)
		if err != nil {
			return total
		}
	}
}

// TestReadMultiBufferSingleSlotInvariants pins the two properties that keep
// Stream.ReadMultiBuffer safe. It returns Buffer.SingleMultiBuffer(), whose
// backing array lives *inside* the pooled slab (buf.managedBuffer.single), so
// the returned MultiBuffer aliases memory that Release() recycles.
//
// It is safe only because the slot array holds exactly one element, which makes
// any append reallocate instead of writing into a recycled slab, and because
// ReleaseMulti clears each slot before releasing its buffer. Growing that array
// or reordering ReleaseMulti reintroduces the defect that shipped once already
// as a nil dereference in readv_reader.go (fixed in 203fe55b).
func TestReadMultiBufferSingleSlotInvariants(t *testing.T) {
	single := buf.New().SingleMultiBuffer()
	if len(single) != 1 || cap(single) != 1 {
		t.Fatalf("SingleMultiBuffer len/cap = %d/%d, want 1/1: appending to it "+
			"would write into the pooled slab", len(single), cap(single))
	}

	// A slot must be cleared while its buffer is still live, never after.
	released := single[0]
	remainder := buf.ReleaseMulti(single)
	if len(remainder) != 0 {
		t.Fatalf("ReleaseMulti returned %d buffers, want 0", len(remainder))
	}
	if single[0] != nil {
		t.Fatal("ReleaseMulti left a released buffer in the slot")
	}
	if released.Len() != 0 {
		t.Fatal("ReleaseMulti did not release the buffer")
	}
}

// TestAbortReleasesQueuedReceiveBudget covers the receive-stall cleanup path,
// which had no direct test: Abort must hand back both the queued buffers and
// the session-wide receive reservation, or the carrier wedges once the window
// is exhausted.
func TestAbortReleasesQueuedReceiveBudget(t *testing.T) {
	const payload = 2048

	client, server := testSessionPair(t, func(config *Config) {
		config.MaxFrameSize = payload
		config.MaxStreamBuffer = payload * 2
		config.MaxReceiveBuffer = payload * 2
		config.StreamStallTimeout = 20 * time.Millisecond
	})

	body := make([]byte, payload)

	// Fill a stream's window and abandon it, then abort.
	stalled, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = stalled.SetWriteDeadline(time.Now().Add(time.Second))
	for range 2 {
		if _, err := stalled.Write(body); err != nil {
			t.Fatalf("priming write: %v", err)
		}
	}
	waitForBuffered(t, accepted, payload*2)

	if err := accepted.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	// The reservation must be back: the whole receive budget was held by the
	// aborted stream, so anything left behind wedges the next stream.
	server.receiveMu.Lock()
	used := server.receiveUsed
	server.receiveMu.Unlock()
	if used != 0 {
		t.Fatalf("receiveUsed = %d after abort, want 0: budget leaked", used)
	}

	if _, err := accepted.ReadMultiBuffer(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("aborted stream read error = %v, want ErrClosedPipe", err)
	}

	next, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = next.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := next.Write(body); err != nil {
		t.Fatalf("write after abort: %v", err)
	}
	follower, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	mb, err := follower.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read after abort: %v", err)
	}
	if mb.Len() != payload {
		t.Fatalf("read %d bytes after abort, want %d", mb.Len(), payload)
	}
	buf.ReleaseMulti(mb)
}

func waitForBuffered(t *testing.T, stream *Stream, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stream.stateMu.Lock()
		buffered := stream.buffered
		stream.stateMu.Unlock()
		if buffered >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stream never buffered the primed frames")
}

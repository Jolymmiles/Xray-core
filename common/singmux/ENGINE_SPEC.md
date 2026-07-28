# Embedded SMUX v1 engine

The carrier is an ordered full-duplex byte stream. Every frame starts with an
8-byte header:

| Offset | Size | Field | Encoding |
| --- | ---: | --- | --- |
| 0 | 1 | version | `1` |
| 1 | 1 | command | `0` open, `1` close, `2` data, `3` keepalive |
| 2 | 2 | payload length | unsigned little endian |
| 4 | 4 | stream ID | unsigned little endian |

Open, close, and keepalive frames have no payload. Data frames may carry up to
65535 bytes. The implementation emits frames of at most the configured frame
size and treats an invalid version, command, control-frame length, or zero
stream ID as a carrier protocol error.

Client-created stream IDs are odd and begin at 3. Server-created stream IDs are
even and begin at 2. Parity is validated when a peer opens a stream; subsequent
data and close frames retain the opener's ID in either direction. Duplicate
open frames are ignored for compatibility.

Each stream is a full-duplex `net.Conn`. A close frame marks the peer's write
side as finished: already-buffered data is delivered before EOF. A carrier
write already queued before a concurrent close reports its actual write result,
not a synthetic EOF. A local close
discards unread data, sends one close frame, and removes the stream from its
session. Carrier failure wakes all pending stream and accept operations.

Writes enter a bounded FIFO carrier queue as complete wire frames. This gives
each submitted frame an explicit lifetime and prevents caller-buffer reuse from
racing an asynchronous carrier write. Receive memory is bounded at both session
and stream level. Ordinary pressure backpressures the carrier until the
application consumes data. If one stream remains unable to accept a complete
frame for 30 seconds, the engine aborts only that stream, releases its unread
buffers and session receive reservation, and resumes the carrier read loop. The
close notification uses the existing bounded writer queue and never adds a
goroutine; failure to enqueue it fails the carrier closed. Size-class pools
cover the standard frame sizes without retaining arbitrarily large allocations.

The Xray server bounds incomplete SMUX stream handshakes at 512 across the
complete `Service`, not separately per carrier. The slot is released as soon as
the request is validated and the response is written; established streams do
not retain it and are not subject to a hard connection-count cap. Admission is
nonblocking: a handshake above the global pending limit is closed immediately
instead of occupying another goroutine until the 10-second deadline. Carrier
and admitted stream handshakes retain their 10-second deadlines, and context
cancellation closes a blocked carrier immediately.

Keepalive is configurable and disabled by the Xray SMUX integration. When
enabled, each side sends a stream-zero keepalive at the configured interval and
closes the session if no inbound frame arrives before the timeout. A heartbeat
send is allowed the full keepalive timeout; a single delayed scheduler interval
does not terminate an otherwise healthy carrier.

Session shutdown closes and interrupts the carrier, then waits for the read,
write, and optional keepalive loops to exit before `Close` returns. A caller
may release pooled carrier adapters after `Close` without a background SMUX
loop retaining or reading them.

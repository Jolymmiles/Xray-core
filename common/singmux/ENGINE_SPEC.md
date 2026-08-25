# Embedded SMUX v1 engine

The carrier is an ordered full-duplex byte stream. Every frame starts with an
8-byte header:

| Offset | Size | Field | Encoding |
| --- | ---: | --- | --- |
| 0 | 1 | version | `1` |
| 1 | 1 | command | `0` open, `1` close, `2` data, `3` keepalive, negotiated `4` half-close |
| 2 | 2 | payload length | unsigned little endian |
| 4 | 4 | stream ID | unsigned little endian |

Open, close, keepalive, and negotiated half-close frames have no payload. Data frames may carry up to
65535 bytes. The implementation emits frames of at most the configured frame
size and treats an invalid version, command, control-frame length, or zero
stream ID as a carrier protocol error.

Client-created stream IDs are odd and begin at 3. Server-created stream IDs are
even and begin at 2. Parity is validated when a peer opens a stream; subsequent
data and close frames retain the opener's ID in either direction. Duplicate
open frames are ignored for compatibility.

Each stream is a full-duplex `net.Conn` until either endpoint sends a close
frame. SMUX v1 has no separate logical half-close command: command 1 terminates
the peer stream, delivers already-buffered data before EOF, and makes later
writes return EOF. A carrier write already queued before a concurrent close
reports its actual write result, not a synthetic EOF. A local close discards
unread data, sends one close frame, and removes the stream from its session.
Carrier failure wakes all pending stream and accept operations.

When `Config.LogicalHalfClose` is negotiated, command 4 is a directional
write-close with zero payload. Local `CloseWrite` is ordered after accepted data,
rejects later writes, and preserves reads. A received command 4 drains buffered
data before read EOF while keeping writes open. Command 1 retains legacy full
close semantics. Command 4 without negotiated capability is a carrier protocol
error.

A remote stream still owned by the session's accept backlog is removed and its
buffered receive data is released; it is never exposed by a later accept. Once
an accept transfers ownership to the application, buffered data remains
readable before the terminal carrier error.

Writes enter a bounded FIFO carrier queue as complete wire frames. This gives
each submitted frame an explicit lifetime and prevents caller-buffer reuse from
racing an asynchronous carrier write. Receive memory is bounded at both session
and stream level; pressure stops carrier reads until the application consumes
data. Size-class pools cover the standard frame sizes without retaining
arbitrarily large allocations.

The Xray server bounds active SMUX stream handlers at 512. Carrier and stream
handshakes each have a 10-second deadline, and context cancellation closes a
blocked carrier immediately.

Keepalive is configurable and disabled by the Xray SMUX integration. When
enabled, each side sends a stream-zero keepalive at the configured interval and
closes the session if no inbound frame arrives before the timeout. A heartbeat
send is allowed the full keepalive timeout; a single delayed scheduler interval
does not terminate an otherwise healthy carrier.

Session shutdown closes and interrupts the carrier, then waits for the read,
write, and optional keepalive loops to exit before `Close` returns. A caller
may release pooled carrier adapters after `Close` without a background SMUX
loop retaining or reading them.

## Server service lifecycle

`singmux.Service` is the sole lifecycle owner for every admitted SMUX and
H2MUX physical carrier. Admission and the transition to shutdown are
linearized under one private service lock. Once shutdown starts, a new
`NewConnection` call closes its transferred carrier and fails with
`net.ErrClosed` without reading a handshake.

`Service.Close` first stops carrier admission. For every carrier admitted
before that point it stops stream-handler admission, cancels the carrier and
stream contexts, and promptly starts the physical `Close`; one blocked carrier
`Close` does not delay interruption of another carrier. It waits for every
physical close call and then for the carrier registry's terminal barrier, so
every admitted `NewConnection` has returned.

For MPL SMUX, `NewConnection` owns the serving session and joins every admitted
application handler before leaving the registry. Thus each admitted handler's
stream cleanup, presence lease, buffer and credit ownership is terminal before
`Service.Close` returns. A cooperative dispatcher must return after its context
is canceled; otherwise `Service.Close` continues waiting rather than reporting
false completion.

For H2MUX, the observable transport lifecycle seam is `http2.Server.ServeConn`.
`NewConnection` waits for `ServeConn` to return and joins every wrapper
invocation that successfully entered handler admission. A wrapper invocation
that arrives after its carrier starts stopping rejects before dispatcher,
presence lease, stream buffer, or handler ownership is acquired. Private
`x/net/http2` scheduler goroutines outside `ServeConn` and admitted wrapper
invocations are not owned or claimed as joined by `Service`.

Concurrent calls to `Close` are safe and observe the same terminal result.

`common/mux.Server` coordinates shutdown but does not own a second carrier
registry. Its `Close` delegates to both `singmux.Service` and the legacy mux
runtime and preserves errors from both paths. These lifecycle rules do not
change SMUX or H2MUX wire bytes.

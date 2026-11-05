# VLESS behavior and performance baseline

Baseline ID: `vless-v0-behavior-2026-07-17`

This baseline fixes the observable behavior of the plain VLESS v0 TCP and Mux
paths before production optimization. XTLS/Vision, UDP framing, fallback
routing, and the optional VLESS encryption handshake remain outside this first
measurement and must retain their existing tests and process gates when a
shared code path changes.

## Source and conditions

- Xray commit: `8e3f90260e0887d12bef3b54d38fd18818fd2cfb` plus the
  characterization test in `encoding/behavior_test.go`.
- Host: darwin/arm64, Apple M3 Max, Go 1.26.5.
- Benchmark command:

  ```sh
  go test ./proxy/vless/encoding -run '^$' \
    -bench 'Benchmark(Encode|Decode)(Request|Response)Header' \
    -benchmem -benchtime=2s -count=5
  ```

## Frozen wire behavior

The deterministic user ID is `00112233-4455-6677-8899-aabbccddeeff`.

| Message | Hexadecimal wire representation |
| --- | --- |
| TCP to `example.com:443` | `0000112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d` |
| TCP to `192.0.2.1:443` | `0000112233445566778899aabbccddeeff000101bb01c0000201` |
| TCP to `[2001:db8::1]:443` | `0000112233445566778899aabbccddeeff000101bb0320010db8000000000000000000000001` |
| Mux command | `0000112233445566778899aabbccddeeff0003` |
| Empty response | `0000` |

The characterization suite also fixes these stream semantics:

- a valid header decoded from the inbound first buffer is not classified as a
  fallback;
- bytes received after that header remain available as the first payload;
- every split between byte 18 and the end of domain, IPv4, IPv6, and Mux
  headers falls back to the streaming decoder without losing payload bytes;
- plain TCP has no body framing or transformation;
- the outbound buffers the request header and waits up to 500 ms for an
  immediately available first payload before flushing, whether or not the
  dispatcher gave the link reader a timeout; with Vision, a wait that ends
  without a payload sends a padding-only block after the header;
- the inbound buffers the response header and flushes it with the first
  response payload.

## TCP half-close lifecycle

A successful upload EOF on a TCP request is propagated as a write-half close
when the outbound connection supports `CloseWrite`. The download direction
remains open until the peer response and EOF have been delivered. This applies
to plain TCP, TLS, and REALITY VLESS carriers and does not add VLESS bytes. On
TLS and REALITY the write-half close is `CloseWrite` of the TLS connection,
which sends a close_notify alert: a 19-byte application-data record in TLS
1.3, right after the last payload of that direction. Upstream sends the same
alert from the client only when it closes the whole connection, after the
one-second uplink-only/downlink-only timeout; the 2026-10-27 capture saw no
server alert from upstream before the client closed.
Transports without half-close support retain their existing lifecycle. This
baseline covers one VLESS connection per TCP/TLS/REALITY carrier; it does not
establish SMUX logical-stream half-close support.

The Linux process regression covers TLS and REALITY, with and without Vision,
plus SOCKS/Freedom and Dokodemo/Freedom controls:

```sh
GOTOOLCHAIN=auto go test -tags integration ./common/singmux \
  -run '^(TestShortOriginHalfCloseControl|TestShortSOCKSHalfCloseControl|TestDokodemoHalfCloseControl|TestVLESSShortConnectionStability)$' \
  -count=1 -v
GOTOOLCHAIN=auto go test -tags integration ./common/singmux \
  -run '^TestVLESSShortConnectionBurstStress$' -count=5 -v
```

## Header baseline

Medians of five runs:

| Operation | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Encode TCP/domain request | 113.2 | 172 | 6 |
| Decode TCP/domain request | 190.8 | 248 | 7 |
| Encode empty response | 51.66 | 104 | 2 |
| Decode empty response | 64.08 | 104 | 2 |

The request encoder allocation profile attributes almost all objects to
`EncodeRequestHeader`, address/port serialization, and returning the pooled
stack buffer. The decoder adds the returned request/addons objects, domain
construction, address parsing, and the same buffer return. The benchmark uses
a resettable `bytes.Reader`, so its reader does not contribute an allocation.

The existing shared domain-address benchmark records a 37.82 ns median, 20
B/op, and 3 allocs/op, accounting for half of the request encoder's allocation
count.

The inbound first-buffer A/B benchmark records:

| Variant | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Current unmanaged `make` | 915.8 | 8,240 | 2 |
| Owned pooled candidate | 40.38 | 72 | 2 |

The pooled candidate reduces allocated bytes by 99.1% and the isolated setup
time by about 95.6%. The object count is unchanged because both variants expose
the buffer object through the benchmark sink; the material difference is the
8 KiB backing store.

## Optimization worklist

1. **Inbound first buffer.** `inbound.Handler.Process` currently creates an
   unmanaged `buf.Size` byte slice for every accepted connection. Replacing it
   with an owned pooled buffer is the clearest connection-rate and GC target,
   provided fallback handoff and coalesced payload ownership stay unchanged.
2. **Plain header fast path.** Empty addons are the dominant VLESS/SMUX case.
   Encoding directly into caller-owned storage can avoid the temporary pooled
   buffer, interface escapes, and the second header copy while preserving the
   exact bytes above.
3. **Contiguous first-buffer decode.** The common path already has the whole
   header in the first read but parses it through several `io.Reader` calls.
   A bounded contiguous parser can reduce calls and temporary objects, with the
   fragmented-reader path retained as the fallback.
4. **Address serialization.** Domain encoding currently creates temporary
   byte slices for the type/length, port, and string conversion. Prefer a
   buffer-aware specialization; changing the shared protocol parser requires
   benchmarks for its other callers.
5. **Per-connection orchestration.** Contexts, activity timers, task closures,
   logging, and the two `buf.Copy` option closures are plausible setup costs.
   They require a process profile before modification.
6. **First-payload wait.** The 500 ms coalescing window trades a syscall for
   startup latency. It must be evaluated with both immediate-payload throughput
   and delayed/empty-payload latency, not changed from a throughput benchmark
   alone.

Header microbenchmarks characterize connection setup. Linux process-level
VLESS throughput and connection-rate tests remain the acceptance gate for any
production optimization.

## Optimized result

The first optimization pass keeps the frozen behavior above and changes only
the common plain-VLESS setup path:

- inbound first reads now use an owned pooled buffer, with explicit cleanup on
  pre-handoff errors and cleanup of any bytes left in `BufferedReader`;
- empty-addons request and response headers use a single exact-sized write;
- domain, IPv4, and IPv6 serialization is specialized in that plain fast path;
- complete plain headers in the first read use a contiguous decoder, while
  fragmented headers, non-empty addons, and unusual inputs keep the original
  streaming decoder.

Five-run medians after optimization:

| Operation | Baseline | Optimized | Allocated bytes | Allocations |
| --- | ---: | ---: | ---: | ---: |
| Encode TCP/domain request | 113.2 ns | 53.26 ns | 172 -> 128 | 6 -> 2 |
| Encode empty response | 51.66 ns | 30.35 ns | 104 -> 80 | 2 -> 1 |
| First-buffer setup | 677.7 ns | 62.49 ns | 8,240 -> 72 | 2 -> 2 |
| Contiguous TCP/domain decode | 334.9 ns | 209.6 ns | 416 -> 344 | 12 -> 10 |

The first-buffer decode row includes construction of the benchmark's
`BufferedReader`; the same harness is used on both sides. The streaming decode
benchmark is deliberately unchanged and remains the fragmentation control.

Linux/arm64 process gates use locally started Xray, sing-box, and mihomo
binaries:

- VLESS interoperability: 16/16 combinations passed (both peers, both Xray
  directions, TCP and UDP, padding off and on);
- VLESS server full-duplex ratios against sing-mux over three complete runs:
  `0.928`, `0.988`, and `0.938`, all below the `1.10` regression limit;
- reconnect/resource stress kept zero loopback error/drop/CRC/carrier deltas.
  One initial `mihomo` to Xray-server stream was reset; the isolated topology
  then passed five independent runs (15/15 cycles), so the reset is recorded
  as a non-reproduced process-test flake rather than hidden.

Worklist items 1-4 are complete. The broader context/task orchestration in item
5 remains deferred, and the 500 ms coalescing window in item 6 is unchanged.

## TCP setup optimization pass (2026-07-18)

This pass measured and optimized three costs on the plain VLESS TCP setup path.
Results are medians on the baseline host; each steady-state benchmark was run
ten times unless noted otherwise.

| Operation | Before | After | Allocated bytes | Allocations |
| --- | ---: | ---: | ---: | ---: |
| Ready first-payload pipe read | 139.0 ns | 18.27 ns | 248 -> 0 | 3 -> 0 |
| Plain-flow traffic-state selection | 26.6 ns | 1.97 ns | 112 -> 0 | 1 -> 0 |
| Header + 1400-byte first payload | 151.4 ns | 131.9 ns | 184 -> 192 | 6 -> 6 |

The pipe fast path checks already-buffered data before allocating a timer. The
timeout duration and timeout/EOF behavior are unchanged. Plain VLESS no longer
creates the Vision-only traffic state; the Vision control benchmark remains at
112 B and one allocation. `BufferedWriter.SetFlushNext` now transfers the first
payload buffers alongside the header rather than copying their bytes into the
header buffer. It still makes one underlying multi-buffer write; the additional
eight bytes are slice metadata, not payload storage. This transfer was
reverted on 2026-10-27: on TLS and REALITY each buffer of that write became
its own record, so the header left in a record of its own (see "Header and
first payload in one TLS record").

TCP lifecycle characterization also found and fixed two resource leaks:
failed TLS/REALITY/header setup now closes the dialed connection, and listener
wrapping or post-listen configuration errors close the bound listener. These
are correctness fixes and are not counted as throughput improvements.

Acceptance gates for this pass:

- race tests passed for TCP transport, pipe, common buffers, and all VLESS
  packages;
- all local `TestVless*` scenarios passed, including plain, TLS, Vision, and
  REALITY variants;
- Linux/amd64 test binaries cross-compiled for TCP transport, pipe, common
  buffers, VLESS encoding, and VLESS inbound;
- `go vet` reports only the four pre-existing Vision `unsafe.Pointer`
  diagnostics in inbound and outbound.

## Header and first payload in one TLS record (2026-10-27)

The 2026-07-18 transfer of the first payload buffers handed the header to
`BufferToBytesWriter` as a separate slice, and the inbound response prefix
writer did the same with the two-byte response header. `net.Buffers` writes
each slice with its own `Write`, and on TLS and REALITY each `Write` is a
record. Right after the handshake the client therefore sent a record holding
only the request header (43 bytes without flow, 61 with Vision, for an IPv4
destination) and the server a 19-byte record holding only the response
header. Stock Xray sends neither: upstream copies the first payload into the
header buffer and writes both at once. Per-flow constant record sizes are
features a passive classifier can use, so this pass restores upstream's
copy: `BufferedWriter` in flush-next mode and `PrefixWriter` copy the first
payload behind the header and pass the result as one buffer, or as
`buf.Size` chunks when it is larger. The prefix methods on
`BufferToBytesWriter` and `SequentialWriter` are gone.

Record sizes after the handshake on loopback, Xray client and server over
REALITY, sniffing enabled on the client's SOCKS inbound, a 517-byte request
echoed back, four connections per binary (`application data` lengths; the
first client record is the encrypted Finished):

| Binary | Client records | Server records after the handshake |
| --- | --- | --- |
| upstream `1b1647cd`, no flow | `53 560` | `536` |
| fork `72ba70ee`, no flow | `53 43 534` | `19 534` |
| this change, no flow | `53 560` | `536` |
| fork `72ba70ee`, Vision | `53 61 565..754` | `19 590..786` |
| this change, Vision | `53 655..827` | `558..697` |

Every Vision record size varies with its random padding. The trailing 19-byte
record each direction still shows in the fork is the close_notify of the
write-half close described above, not a VLESS header. These binaries predate
PR #61, so without sniffing their outbound sent its header before the first
payload arrived; since #61 it waits for the first payload whatever the link
reader, and the integration test below runs without sniffing.

Isolated benchmarks, linux/amd64, AMD Ryzen 9 9950X, Go 1.27.3, CPU governor
`powersave`, host load average 3-4; before and after binaries alternated in
five rounds of two samples, medians of ten:

```sh
go test ./common/buf -run '^$' -benchmem -count=2 \
  -bench 'Benchmark(BufferedWriterHeaderAndFirstPayload|BufferedTCPWriterHeaderAndFirstPayload|PrefixedBufferedTCPWriterHeaderAndFirstPayload|VLESSResponsePrefixWriter|PrefixedBufferedSequentialWriter|IdlePrefixWriter|HeaderAndFirstPayloadOverTLS)$'
```

| Benchmark (1400-byte first payload) | Before | After | Bytes | Allocations |
| --- | ---: | ---: | ---: | ---: |
| Request header over TLS | 3.630 µs | 2.161 µs | 153 -> 160 | 4 -> 5 |
| Response header over TLS | 3.630 µs | 2.203 µs | 104 -> 160 | 3 -> 5 |
| `BufferedWriter` flush-next, recording writer | 75.99 ns | 81.51 ns (~) | 168 -> 160 | 5 -> 5 |
| `PrefixWriter` to `io.Discard` | 69.63 ns | 87.30 ns | 240 -> 273 | 5 -> 6 |
| Prefixed `SequentialWriter` to `io.Discard` | 59.38 ns | 70.75 ns | 168 -> 176 | 5 -> 6 |

The TLS benchmarks write through a real `crypto/tls` client on loopback and
are the path a connection takes: one sealed record and one system call
instead of two. The writer-only benchmarks add the copy of the first payload
and one slice allocation; they write to `io.Discard` and miss the record cost.
The process benchmark (`BenchmarkVLESSTCPProcess`, 50 connections, five
samples each) shows no significant change: TLS no flow 1.263 -> 1.263 ms,
TLS Vision 1.259 -> 1.328 ms (p=0.84), REALITY no flow 1.523 -> 1.491 ms,
REALITY Vision 1.504 -> 1.540 ms (p=0.55). It ran before PR #61: its client
has no sniffing, so only the server side changed there.

Regression tests: `TestHeaderAndFirstPayloadShareOneTLSRecord` and
`TestHeaderWithLargeFirstPayloadKeepsBytesAndLeadsWithPayload`
(`common/buf/writer_tls_record_test.go`) count the records of a real TLS
client, and the integration test
`TestVLESSTCPHeaderSharesTLSRecordWithFirstPayload`
(`common/singmux/vless_tcp_record_integration_test.go`) reads the records
between an Xray client and server over TLS and REALITY, with and without
Vision.

## TLS, REALITY, and Vision process baseline (2026-07-18)

This baseline starts a local Xray VLESS TCP server and a long-lived local Xray
SOCKS/VLESS client. Every measured operation opens a fresh SOCKS connection,
which creates a fresh VLESS transport connection, completes TLS or REALITY,
round-trips an echo payload, and closes the connection. Process startup and
the readiness warm-up are outside the timed region.

The host is darwin/arm64, Apple M3 Max, Go 1.26.5. These are medians of five
fixed 50-connection samples:

| Server mode | Connection round trip |
| --- | ---: |
| TLS, no flow | 3.296 ms/op |
| TLS, Vision | 3.223 ms/op |
| REALITY, no flow | 3.728 ms/op |
| REALITY, Vision | 3.838 ms/op |

The command is deliberately bounded to avoid exhausting the macOS ephemeral
port range during rapid TLS/REALITY connection churn:

```sh
go test -tags integration ./common/singmux -run '^$' \
  -bench '^BenchmarkVLESSTCPProcess$' -benchtime=50x -count=5
```

The corresponding correctness gate covers Xray, sing-box, and Mihomo clients
across all four modes (12 scenarios). Three complete post-change runs passed,
for 36/36 scenario executions.

The first measured Vision optimization replaces two reflection field searches
per connection with checked, per-concrete-type cached offsets shared by the
inbound and outbound paths. Its isolated five-run median changed from 51.97 ns
to 12.34 ns (76.3% lower), with zero allocations before and after. Invalid or
changed TLS layouts are now rejected instead of silently interpreting offset
zero as a `bytes.Reader` or `bytes.Buffer`.

The process numbers are regression baselines, not evidence for a 40 ns change:
cryptographic handshake and scheduling noise dominate their millisecond scale.
Linux runtime measurements remain required before making release-level server
capacity claims; the Darwin gate proves behavior and gives a reproducible local
directional signal only.

## Removed-user connection tracking (2026-10-12)

`Process` now tracks every connection it authenticates for a user with an
email, so `RemoveUser` can close it (`proxy.UserConnections`). The cost is
per connection, at setup and teardown; nothing runs per packet. Linux/amd64
(Debian 13, kernel 6.12, 32 CPUs, `powersave` governor, not changed), Go
1.27.2, `GOFLAGS=-tags=http2legacy`, candidate `0906ebf7` against baseline
`9ce136ea`.

Microbenchmarks, medians of five runs:

```sh
go test ./proxy/vless/inbound -run '^$' -bench 'BenchmarkProcess' -benchmem -count=5
go test ./proxy -run '^$' -bench 'BenchmarkUserConnections' -benchmem -count=5
```

| Operation | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Worker context alone (control) | 61.0 | 96 | 2 |
| Worker context + tracking, real validator, 1 user | 298.1 | 624 | 8 |
| Worker context + tracking, real validator, 10,000 users | 338.0 | 624 | 8 |
| Same, 32 goroutines, 1,024 users | 727.6 | 624 | 8 |

Tracking adds about 240 ns and 6 allocations per connection. A memory
profile attributes them to the connection's own context and its cancel
function, the tracked entry, and the parent's child map and done channel;
the last two are allocated anyway once downstream code derives a context
from the worker's, which now happens on the tracked one instead.

Process benchmark: one Xray server and one Xray client per mode, a new VLESS
connection per operation; the client binary is the candidate in every run
and only the server changes. Three rounds alternating baseline and candidate
servers, five samples of 200 connections each, so 15 samples per cell:

```sh
XRAY_E2E_BIN=<candidate> XRAY_E2E_SERVER_BIN=<baseline|candidate> \
  go test -tags 'integration http2legacy' ./common/singmux -run '^$' \
  -bench '^BenchmarkVLESSTCPProcessUserEmail$' -benchtime=200x -count=5
```

| Server mode | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| TLS, no flow, email | 1.222 ms | 1.227 ms | +0.4% |
| TLS, no flow, no email | 1.224 ms | 1.226 ms | +0.2% |
| TLS, Vision, email | 1.241 ms | 1.252 ms | +0.9% |
| TLS, Vision, no email | 1.247 ms | 1.228 ms | -1.5% |
| REALITY, no flow, email | 1.486 ms | 1.479 ms | -0.5% |
| REALITY, no flow, no email | 1.471 ms | 1.506 ms | +2.3% |
| REALITY, Vision, email | 1.484 ms | 1.505 ms | +1.4% |
| REALITY, Vision, no email | 1.481 ms | 1.485 ms | +0.3% |

The baseline and candidate sample ranges overlap in every cell, and the
cells without an email, which take no tracking path, move as much as those
with one: the process benchmark shows no regression beyond noise. It is a
regression gate, not evidence for the 240 ns figure, which the
microbenchmark measures. Not measured: throughput of established
connections, which tracking does not touch, and contention at connection
rates above what one client process generates.

## Inbound connection tracking for removal (2026-10-12)

Every TCP and Unix socket worker now tracks the connections it serves, so
closing the inbound ends them. Same host and conditions as the section
above; candidate is the branch fix/remove-inbound-closes-connections against
`47108c0d`.

```sh
go test ./app/proxyman/inbound -run '^$' -bench '^BenchmarkTCPWorkerAcceptedConnection$' -benchmem -count=5
```

Two rounds alternating baseline and candidate, ten samples each: median
160.5 ns, 544 B, 3 allocations per accepted connection before; 215.3 ns,
569 B, 4 allocations after. The tracked entry is the added allocation; the
existing budget of 11 allocations (`TestTCPWorkerAcceptedConnectionAllocationBudget`)
holds.

`BenchmarkVLESSTCPProcessUserEmail`, run as above (three rounds, 15 samples
per cell, the candidate client against both servers), moved between -1.4%
and +1.8% per cell with overlapping ranges: no change beyond noise.

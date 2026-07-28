# SMUX v1 baseline

Baseline ID: `smux-mpl-v1-2026-07-17`

This is the pre-hardening baseline for the in-tree MPL-2.0 SMUX stack. It is a
historical measurement, not a promise that absolute timings remain identical on
different hardware. Release decisions use the peer-relative ratio and invariant
gates below.

## Source identity

| Component | Identity |
| --- | --- |
| Xray base commit | `50231eaff98ccc31b5cbd247a721c16e97fe5ec1` (`main`, dirty SMUX working tree) |
| Xray Linux binary | `Xray 26.7.11 50231ea-dirty`, Go 1.26.5, linux/arm64, CGO disabled |
| SMUX production/spec digest | SHA-256 `e9a5255800ba7f3e65294aaf738547f4b195c6d79e6217d9b23c4f259f98c1cf` |
| sing-box source/binary revision | `46f00de9aa060ab989353953051268c7c4745664`, Go 1.26.5, linux/arm64, CGO disabled |
| Mihomo source checkout | `2e1394a7cf4c2d25ac6290a05ee0e21f786073de` (`Prerelease-Alpha-583-g2e1394a7-dirty`) |
| Mihomo binary | `Mihomo Meta 1.10.0`, Go 1.26.5, linux/arm64 |
| Linux image | `debian:12`, `sha256:d57f83d49c5392019608bc71463a7e9d9d562cbc33c93138ae5b46bf39adff15` |

The SMUX digest is produced from sorted non-test `.go` and `.md` files under
`common/singmux`, excluding this baseline file:

```sh
find common/singmux -type f \( -name '*.go' -o -name '*.md' \) \
  ! -name '*_test.go' ! -name BASELINE.md -print0 \
  | sort -z | xargs -0 shasum -a 256 | shasum -a 256
```

## Functional baseline

The real-process interoperability matrix passed 32/32 scenarios in 2.21 s:

- peers: sing-box and Mihomo;
- directions: Xray client and Xray server;
- carriers: VLESS and Trojan;
- payload networks: TCP and UDP;
- padding: disabled and enabled.

The stress/reconnect matrix passed all eight peer/direction/carrier topologies,
three cycles each, in 23.88 s. Every cycle used 128 concurrent full-duplex TCP
streams with 1 MiB in each direction and 10,000 UDP datagrams across four
destinations. The server carrier was killed and restarted between cycles.

Linux loopback counters started at zero and every checked delta remained zero:
RX/TX errors, RX/TX drops, RX CRC errors, TX carrier errors, collisions, and
carrier changes.

Observed client-process RSS KiB and threads after cycles 1/2/3:

| Topology | RSS KiB | Threads |
| --- | --- | --- |
| sing-box / Xray client / VLESS | 33368 / 33584 / 33716 | 9 / 9 / 11 |
| sing-box / Xray client / Trojan | 33996 / 34276 / 34456 | 10 / 10 / 10 |
| sing-box / Xray server / VLESS | 66068 / 80192 / 89288 | 10 / 10 / 10 |
| sing-box / Xray server / Trojan | 59812 / 82028 / 86080 | 10 / 10 / 10 |
| Mihomo / Xray client / VLESS | 33192 / 33484 / 33640 | 10 / 10 / 10 |
| Mihomo / Xray client / Trojan | 34332 / 34532 / 34560 | 9 / 9 / 9 |
| Mihomo / Xray server / VLESS | 38204 / 48676 / 61028 | 11 / 11 / 11 |
| Mihomo / Xray server / Trojan | 63080 / 64276 / 57604 | 10 / 10 / 10 |

For `Xray server` rows, the observed client process is sing-box or Mihomo; the
numbers therefore must not be attributed to the Xray server.

## Performance baseline

Five alternating rounds, 128 full-duplex TCP streams, 1 MiB each way:

| Carrier | Xray SMUX median | sing-mux median | Ratio |
| --- | ---: | ---: | ---: |
| VLESS | 232.961 ms | 251.830 ms | 0.925 |
| Trojan | 356.589 ms | 307.909 ms | 1.158 |

The Linux release gate is the VLESS ratio `<= 1.10`; this baseline is about
7.5% faster than the sing-mux peer. Trojan remains diagnostic because that
comparison also includes different TLS and Trojan implementations.

## Code-quality baseline

- `common/singmux`: 80.0% statement coverage;
- `common/singmux/internal/mplsmux`: 85.3% statement coverage;
- race tests pass for `common/singmux/...` and `common/mux`;
- the production dependency graph contains no Sagernet, Metacubex, Hashicorp,
  `common/singbridge`, or other external mux implementation;
- `go.mod`, `go.sum`, and `common/singbridge` are unchanged.

## Reproduction

The canonical commands and build tags are maintained in `TESTING.md`. A valid
new baseline must use fresh binaries from one working tree and run compatibility,
stress/health, and performance sequentially so the performance measurement is
not contaminated by another workload.

## Hardened result

Hardening result ID: `smux-mpl-v1-hardened-2026-07-17`

This result keeps the historical baseline above intact and records the final
state after the TDD, reconnect, allocation, and Linux server passes. The
production/spec digest is SHA-256
`8c03190a77cd46f347d070f4a61e8eadd1fc59168b16f6fbb79930e69c6d3e77`.

- Real-process interoperability: 32/32 in 2.10 s.
- Linux reconnect stress: 400/400 cycles in 380.61 s across all eight
  peer/direction/carrier topologies.
- Focused Mihomo server / Xray client / Trojan reconnect regression: 50/50 in
  72.34 s.
- Every loopback health delta remained zero: RX/TX errors, RX/TX drops, RX CRC
  errors, TX carrier errors, collisions, and carrier changes.
- No topology showed linear RSS or thread growth.
- Local SMUX tests passed with `-count=50`; race tests passed for
  `common/singmux/...` and `common/mux`.
- Statement coverage: `common/singmux` 79.8%, embedded engine 84.9%, combined
  82.1%.
- The 32 KiB engine benchmark retained 4 allocations/op and 276–309 B/op over
  five runs. Host scheduling produced 1.82–6.15 GB/s, so Linux process ratios
  remain the release performance gate.
- Five-second fuzz passes executed 258,093 outer-protocol, 242,728 padding, and
  1,597,445 frame-header cases without a failure.

The final Linux performance runs use nine alternating rounds each:

| Run | VLESS ratio | Trojan ratio |
| ---: | ---: | ---: |
| 1 | 0.972 | 1.129 |
| 2 | 0.982 | 1.115 |
| 3 | 0.988 | 1.133 |

All VLESS runs pass the `<= 1.10` release gate. Trojan remains diagnostic for
the same cross-TLS/cross-carrier reason documented above.

## 20-pass performance result

Performance result ID: `smux-mpl-v1-performance-20-2026-07-17`

The final SMUX production/spec digest is SHA-256
`9f3e27e9ee8134b541ccee17c0b1179e387c392b20061e499848198b2963d526`.

Twenty bounded optimization passes were run against the hardened result. Each code
variant was measured independently and reverted when it did not improve the
relevant single-stream, multi-stream, lifecycle, or Linux process workload.

| Pass | Hypothesis | Result |
| ---: | --- | --- |
| 1 | Skip receive timestamps when keepalive is disabled | kept |
| 2 | Encode the frame header directly into the pooled frame | kept |
| 3 | Reuse the per-stream data completion channel | kept |
| 4 | Use an RWMutex for the stream map | reverted |
| 5 | Split receive and transmit buffer pools | reverted |
| 6 | Replace receive accounting mutexes with atomics | reverted |
| 7 | Signal session backpressure only when blocked | reverted |
| 8 | Signal stream backpressure only when blocked | kept |
| 9 | Signal readers only when blocked | reverted |
| 10 | Reduce the write backlog from 1024 to 256 | kept |
| 11 | Reduce the write backlog to 64 | reverted |
| 12 | Match the accept backlog to the 512-stream server limit | kept |
| 13 | Reduce the write backlog to 128 | reverted |
| 14 | Reduce the write backlog to 192 | reverted |
| 15 | Replace the zero-deadline no-op stopper with a nil fast path | reverted |
| 16 | Allow concurrent submit readers with an RWMutex | reverted |
| 17 | Add lifecycle and concurrent-stream benchmark coverage | kept |
| 18 | Reuse completion channels for stream open and close | kept |
| 19 | Reuse one completion channel for the keepalive loop | kept |
| 20 | Tighten the hot-path allocation release gate to zero | kept |

The committed-state local 32 KiB round-trip median was 12.141 us, 4 allocs/op,
and 282--289 B/op. The final five-run snapshot is 10.025 us, 0 allocs/op, and
0--1 B/op: a 17.4% latency reduction with all measured heap allocations
removed. The new lifecycle benchmark records a 5.283 us median, 2,338 B/op,
and 28 allocs/op; its pre-reuse snapshot was 5.638 us, 2,723 B/op, and 34
allocs/op. Matching the accept backlog to the server limit reduced a session
pair snapshot from 41,283 to 32,067 B/op.

Fresh linux/arm64 binaries from the final tree passed the 32/32 sing-box and
Mihomo interoperability matrix in 2.16 s. The three-cycle reconnect suite
passed all eight topologies (24/24 cycles) in 22.00 s. Historical loopback
counters were not cleared; RX/TX errors, RX/TX drops, RX CRC errors, TX carrier
errors, collisions, and carrier changes all had zero delta.

Three final nine-round Linux server comparisons produced:

| Run | VLESS ratio | Trojan ratio |
| ---: | ---: | ---: |
| 1 | 0.953 | 1.168 |
| 2 | 1.006 | 1.170 |
| 3 | 1.015 | 1.117 |

The VLESS median ratio is 1.006 and all runs remain below the 1.10 release
limit. The local engine baseline is decisively surpassed; the process-level
peer ratio remains scheduling-sensitive and this final snapshot is 2.4% above
the hardened snapshot's 0.982 median. Trojan remains diagnostic because it also
measures different TLS and Trojan implementations.

## Carrier lifecycle fix (2026-07-19)

A VLESS server stress run exposed a shutdown race: an SMUX session could close
its `done` channel and return from the synchronous dispatch path while its
carrier read loop was still blocked. VLESS then released its pooled reader and
the surviving read loop dereferenced the cleared reader.

The lifecycle contract now has two permanent regression checks:

- generic and pooled buffer readers propagate interruption to their underlying
  closable connection;
- `Session.Close` does not return until its read, write, and optional keepalive
  loops have exited.

The affected unit packages pass normally, with `-race`, and with
`-d=checkptr=2`. The real-process interoperability matrix passed 40/40 current
Xray, sing-box, and Mihomo scenarios. The three-cycle stress/reconnect gate
passed all eight topologies (24/24 cycles) with 128 concurrent full-duplex TCP
streams per cycle and no panic or stuck shutdown.

The five-run 32 KiB stream round-trip result remained at zero allocations and
10.058--10.293 us/op. The session-pair lifecycle used 32,131 B/op and 36
allocations/op; the additional join state is outside the stream data hot path.

## Streaming padding reader (2026-07-21)

This pass targets the padded carrier receive path on the Xray server. The old
reader allocated and filled the complete payload of each of the first 16
padding frames before returning any bytes. That both delayed fragmented input
and duplicated the SMUX receive buffer. The optimized reader keeps only the
four-byte frame header and the remaining payload/padding counters; it streams
payload directly into the caller's buffer and discards padding before exposing
the raw tail. The wire format and the 16-frame transition are unchanged.

The source point is commit `1c2f152b9cba6d6de3215da1a3358b230dd37090`
with a dirty SMUX optimization tree. Measurements used Go 1.26.5 on
darwin/arm64, Apple M3 Max, Darwin 25.5.0. Five samples were collected with:

```sh
go test ./common/singmux -run '^$' \
  -bench '^BenchmarkPaddingRead16Frames$' -benchmem -count=5
```

The benchmark reads sixteen 8 KiB payload frames with 32 bytes of padding per
frame and then the first raw byte. The exact pre-change samples were
18.121--20.999 us/op, with an 18.617 us median, 132,140 B/op, and 50
allocations/op. Two post-change five-sample snapshots were 2.733--3.794 us/op;
the later snapshot median was 2.916 us/op, with 128 B/op and 2 allocations/op.
This is an 84.3% median latency reduction, 99.9% fewer allocated bytes, and
96% fewer allocations in the isolated primitive. A permanent allocation gate
holds the same 16-frame read to at most two allocations.

The complete deterministic RemnaNode server configuration also passed a
Darwin process smoke at a 96 MiB target: the Xray server grew from 39,280 KiB
RSS to 99,008 KiB with 704 held VLESS/REALITY SMUX streams and served the
post-pressure control request. Its profiles are not a Linux capacity result.
The authoritative 5 GiB run, interface/TCP counters, and runtime comparison
remain pending on Linux/amd64. The current Linux/amd64 integration/stress test
binary cross-build proves portability only.

## Owned SMUX receive buffers (2026-07-21)

The next profile-driven pass removes the second 8 KiB payload buffer from the
Xray server's normal SMUX-to-dispatcher path. Receive frames up to Xray's
standard buffer size are now read directly into an owned `buf.Buffer`, and
`Stream.ReadMultiBuffer` transfers that ownership to the existing pipeline.
The regular `net.Conn.Read` API, partially consumed frames, large frames, per-
stream backpressure, and the wire format retain their previous behavior.
Frames larger than 8 KiB keep the zero-allocation engine pool and use the
copying adapter only when a `MultiBuffer` consumer requests them.

The permanent 8 KiB comparison runs the same engine and payload through the
old adapter-copy shape and the owned-transfer path:

```sh
go test ./common/singmux/internal/mplsmux -run '^$' \
  -bench '^BenchmarkStreamReadMultiBuffer8KiB$' -benchmem -count=5
```

The adapter-copy median is 3.360 us/op, 8 B/op, and 1 allocation/op. The
owned-transfer median is 2.901 us/op, 0 B/op, and 0 allocations/op: 13.7%
lower latency with the payload copy and measured allocation removed. The
existing 32 KiB generic stream round-trip gate remains at zero allocations;
its five-sample median is 10.544 us/op, 5.2% above the documented 10.025 us
snapshot. That generic `io.Reader` cost is recorded as a tradeoff rather than
hidden; the production server-owned path improves by 13.7%, and the Linux
process gate remains authoritative.

At the same 704-stream RemnaNode Darwin smoke point, sampled live heap fell
from 28,839.30 KiB to 18,052.94 KiB (37.4%). The previous separate SMUX
receive-buffer attribution disappeared; `common/buf.New` became the largest
remaining owned-buffer site. RSS changed from 99,008 KiB to 100,656 KiB, a
1.7% increase that is consistent with allocator/GC residency noise and is not
claimed as a resident-memory improvement. Linux 5 GiB RSS, GC, throughput,
latency, and network-counter evidence is still required before release.

The post-change Xray-server compatibility matrix passed 24/24 cells: Xray,
sing-box, and Mihomo clients; VLESS and Trojan; TCP and UDP; padding disabled
and enabled. The first run exposed a deterministic Mihomo readiness defect in
the harness: its SOCKS listener and `Initial configuration complete` message
preceded a usable `GLOBAL` provider. The gate now proves a complete
SOCKS-to-Xray-to-echo path before the single-shot scenario assertion. The
previously failing cell passed in isolation, followed by the complete 24/24
server matrix.

The server-only reconnect/stress gate then passed 12/12 cycles in 70.90 s:
sing-box and Mihomo clients, VLESS and Trojan, three Xray-server restarts per
topology. Each cycle retained the standard 128 concurrent full-duplex TCP
streams and 10,000 UDP datagrams. Darwin supplied functional evidence only;
Linux interface counters remain a release gate.

## Direct VLESS response and consumed-buffer retention (2026-07-21)

This pass moves the process-profile priority from SMUX to ordinary physical
VLESS TCP connections. The unchanged deterministic RemnaNode server fixture
was exercised through both REALITY inbounds with four Xray clients that had
both `smux` and `mux` removed. The initial source point was commit `4199e955`
with an unrelated dirty documentation tree. Measurements used Go 1.26.5 on
darwin/arm64, Apple M3 Max. Darwin is functional and comparative evidence only;
Linux/amd64 remains the release-performance target.

The first retained object was the 8 KiB `BufferedWriter` buffer used only to
hold the two-byte VLESS response header until the target returned its first
payload. A dedicated inline `PrefixWriter` now retains those two bytes without
a payload buffer and emits them exactly once with the first response write.
The second retained object was the already-consumed first VLESS request buffer.
`BufferedReader.ReadMultiBuffer` now releases an empty buffered input before it
blocks on the underlying connection. Both ownership changes have focused
regression tests, including concurrent response writes and the consumed-input
transition.

The process comparison used the same 96 MiB diagnostic target for every run:

```sh
XRAY_REMNANODE_DIRECT_MEMORY_PROFILE=1 \
XRAY_REMNANODE_MEMORY_TARGET_BYTES=100663296 \
XRAY_REMNANODE_PROFILE_DIR=/tmp/xray-remnanode-direct \
go test -tags 'integration stress' ./common/singmux \
  -run '^TestRemnaNodeDirectServerMemoryProfile$' -count=1 -v -timeout=10m
```

| Snapshot | Connections at target | Linear RSS slope |
| --- | ---: | ---: |
| Before | 512 at 102,800 KiB | 122.233 KiB/connection |
| Inline response prefix | 576 at 100,992 KiB | 106.171 KiB/connection |
| Inline prefix + consumed-input release | 640 at 100,576 KiB | 98.918 KiB/connection |

The final measured slope is 19.1% lower. The fixed-threshold connection count
is 25% higher, but that figure also includes process-baseline RSS variation and
must not be treated as a Linux capacity claim. The pre-change sampled heap
attributed 2,066.56 KiB to `NewBufferedWriterWithPrefix`; that retained site is
absent after the change. Every run completed post-pressure HTTP forwarding
through both server inbounds.

The isolated two-byte VLESS response benchmark used five two-second samples.
The existing buffered variant had a 147.1 ns/op median; the inline variant had
a 137.9 ns/op median, 6.3% lower, with both at 240 B/op and five allocations
for the full benchmark operation. Constructing an idle inline prefix writer
had an 18.52 ns/op median, 48 B/op, and one allocation, compared with the
pre-change buffered construction's approximately 894.1 ns/op, 9,527 B/op, and
two allocations.

The final process interoperability gate passed 36/36 executions: Xray,
sing-box, and Mihomo clients across TLS/no-flow, TLS/Vision,
REALITY/no-flow, and REALITY/Vision, repeated three times. Unit, race,
checkptr, and vet gates passed. A static stripped Linux/amd64 `GOAMD64=v1`
cross-build passed; Linux runtime, 5 GiB pressure, and network-counter evidence
remain mandatory before a release capacity claim.

## Stalled-stream cleanup and 78k handshake scalability (2026-07-21)

Two focused RED tests reproduced the server failure modes. With a one-frame
stream buffer, a second DATA frame blocked the single carrier read loop, so the
FIN behind it and every unrelated stream remained unread. Separately, the
512-handler semaphore was constructed inside `Service.NewConnection`, allowing
every new carrier to create another 512 blocked handlers. A second carrier
therefore bypassed a saturated first carrier, and overload waited for the full
stream-handshake deadline. The pressure fixture configures only eight streams
per carrier, so 78,000 held streams imply roughly 9,750 carrier sessions before
accounting for retries; this is a scheduler, goroutine, socket, and GC explosion
rather than evidence of a stream-ID limit.

The receive path now preserves normal backpressure but gives a continuously
full stream 30 seconds to make progress. Only after that interval does it abort
the stalled stream, release all unread receive ownership, enqueue a bounded
close notification, and continue the same carrier read loop. The timer is
created only after actual saturation. An initial immediate-abort prototype was
rejected because the race-enabled 1 MiB stale-carrier regression test showed
that a healthy transient burst can briefly fill the 64 KiB stream buffer.

Server admission now uses one nonblocking 512-slot pending-handshake semaphore
per `Service`. A slot covers only request parsing and response writing; it is
released before dispatch, so established streams are not count-capped. The
513th simultaneous incomplete handshake is closed immediately on any carrier
instead of waiting for the 10-second deadline. A RED regression test with a
two-slot limit proved that the previous active-lifetime ownership rejected a
third fully handshaken stream; the corrected implementation keeps all three
active. The held-stream SMUX profile therefore remains a real 5 GiB pressure
test rather than stopping at 512 connections.

The complete service handshake was then run 78,000 times on one carrier to
isolate cumulative stream-ID/map behavior from concurrency. Five final
post-correction samples were 30.454--50.761 us/op, with a 35.446 us median,
about 3,444 B/op, and 56 allocations/op; every sample completed without a
late-run timeout or 78k failure. The wide Darwin scheduler spread makes this a
diagnostic rather than a latency improvement claim. CPU, block, and mutex
profiles from an
additional fixed run reported 112.17 ms total mutex delay across all 78,000
operations, mostly in runtime scheduler/GC unlock paths rather than one engine
lock. Blocking was dominated by ordered `net.Pipe`/channel synchronization.
On this Darwin/arm64 host that evidence rules out a cumulative engine-lock
failure; it does not replace Linux scheduler, RSS, socket, and interface
measurements under concurrent process load.

The existing 32 KiB engine hot path remained at zero allocations. Its current
five-run median was 11.014 us/op versus 11.004 us/op from an isolated clean
worktree at the pre-change commit (+0.09%, measurement noise). Focused race
tests passed 20 times, the full process interoperability matrix passed 40/40
cells, and the reconnect/stress matrix passed 24/24 cycles. Linux runtime and
interface-health evidence remain required before a production capacity claim.
The final static stripped Linux/amd64 `GOAMD64=v1` cross-build has SHA-256
`7ab630e3129cfb3b23c5e3f0ab63f103e9e6010aca8d094ab9365db46e4dedf4` and
completed an amd64 Debian 12 container startup smoke under emulation. That
proves executable portability only; emulation is not Linux/amd64 performance
or network-health evidence.

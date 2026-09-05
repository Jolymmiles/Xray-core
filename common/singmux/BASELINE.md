# SMUX v1 baseline

Current validation policy (2026-09-04): Xray is the only proxy server; Xray,
sing-box, and Mihomo are clients. Performance comparisons use Xray server
versions. Historical entries below retain the topologies and measurements that
were actually used; their external-server comparisons are not current gates.
Use `TESTING.md` and `AGENTS.md` for the current acceptance contract.

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

## Structural online presence release gate (2026-08-13)

The candidate source point for this gate is `87f58be1` with the structural
presence worktree dirty. Validation used Go 1.26.5 on Darwin/arm64. The
repository now has one fail-fast executable entrypoint:
`testing/release/structural_presence.sh`. Its standard mode runs vformat,
repository-wide vet, unit, race, and checkptr plus real SMUX/H2MUX/VLESS
interop, immutable `v26.8.15` version-skew scenarios, and aggregate exact-owner
lifecycle checks. Its Linux mode additionally requires Linux/amd64, a real
`yt` interface and IPv6 assignment, 50 reconnect cycles, the nine-round server
comparison, a minimum 30-minute repeated lifecycle soak, and stripped
`GOAMD64=v1` artifact inspection.

The release workflow pins the validation host to `ubuntu-24.04`, creates the
isolated `yt` interface, and makes every platform build depend on this gate.
The gofumpt dependency is pinned to v0.11.0. Missing environment, wrong host
architecture, absent interface setup, a failed command, or a soak shorter than
1,800 seconds terminates the job; none is converted to a skip.

The release-gate contract, shell syntax, workflow YAML parse, and vformat
check passed on the Darwin host. Initial repository runs exposed external DNS
dependencies, checkptr-distorted allocation budgets, a blackhole test data race,
and process tests that started traffic before complete TCP/UDP forwarding
readiness. The blackhole RED was fixed with a bounded channel handoff. Commander,
VMess mux UDP, and Shadowsocks 2022 UDP now use bounded full-path readiness.

DoH, DoQ, and DNS-over-TCP tests now use local protocol servers that validate
real framing, parsing, cache, A/AAAA filtering, and verified TLS/QUIC behavior;
no external resolver, retry, or skip remains. Allocation budgets remain binding
in normal builds and skip only allocation measurement when build metadata proves
checkptr compiler instrumentation; functional package coverage still runs. After
these corrections, vformat, `go vet ./...`, `go test -timeout 2h ./... -count=1`,
`go test -gcflags=all=-d=checkptr=2 ./... -count=1`, and
`go test -race ./... -count=1` all passed on Darwin/arm64. The canonical
`testing/release/structural_presence.sh standard` entrypoint then passed end to
end, including real SMUX/H2MUX interoperability, all five immutable `v26.8.15`
version-skew process matrices, and aggregate exact-owner lifecycle checks. Task
10.1 is complete. Linux runtime evidence remains pending:
the pinned workflow has not yet run the 50-cycle reconnect gate, nine-round
performance comparison, 30-minute soak, `yt` environment check, Linux network
counter checks, or artifact smoke on this candidate. Therefore this entry
establishes executable non-skippable release wiring, not release readiness or a
Linux capacity/performance claim.

### Critical lifecycle interleavings

A focused candidate gate ran 26 deterministic barrier-controlled tests across
`common/session`, `common/task`, `app/stats`, `app/dispatcher`,
`app/proxyman/inbound`, `common/mux`, `app/reverse`, both VLESS owner packages,
and `proxy/wireguard` with `-race -count=100`. All ten packages passed. The
matrix covered concurrent reservation terminals, exact generation isolation and
batch replacement, callback join, accepted-connection ownership, transactional
session publication/shutdown, response-sink and authorized-transaction drain,
SMUX plus legacy-runtime shutdown ordering, XUDP concurrent rebind and every
blocked close boundary, Bridge/Portal construction and heartbeat joins,
reverse-handler late registration/delayed start, and WireGuard concurrent
admission/roam plus final drain.

Every selected test has an explicit terminal assertion or bounded join, so the
result verifies zero residual exact slots/leases, callbacks, published
resources, response buffers/pumps, runtime schedulers/timers, owner workers, and
test-owned goroutines for those interleavings. The earlier aggregate tests
separately cover 7,000 exact owners, 1,000 XUDP rebinds, 1,000 RVS slots, and
1,000 WireGuard handoffs ending at zero.

### Release platform artifact matrix

The complete official Linux matrix was cross-built from dirty source point
`87f58be1` with Go 1.26.5, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
stripping/build-id release linker flags, and the workflow's architecture-specific
optimization flags. Seventeen binaries passed: amd64 (`GOAMD64=v1`), 386, ARM
v5/v6/v7, arm64, riscv64, loong64, mips64/mips64le, mips/mipsle hard-float and
soft-float, ppc64/ppc64le, and s390x. The first MIPS32 attempt intentionally
proved why the workflow uses package-local `-gcflags=-l=4`: applying
`all=-l=4` fails in the Go runtime with prohibited write barriers. Rebuilding
with the exact workflow branch passed.

`file` reported every artifact as a statically linked, stripped ELF for its
intended architecture. The Linux/amd64 binary ran inside a real linux/amd64
container, reported Xray 26.8.18 at `v26.8.18-4-g87f58be1-dirty`, and accepted a
minimal JSON configuration with `Configuration OK.`. `go version -m` recorded
Go 1.26.5, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`,
`-trimpath`, and `-gcflags=all=-l=4`. Its SHA-256 is
`dd9d625d2004835ff1391de7d6489f95f43ecfa3d0e1f0fd0905d2b88318dafb`.
All 17 artifact hashes and inspection files are retained under
`/tmp/xray-release-matrix-87f58be1`; they are verification artifacts, not
release assets and were not added to the repository.

### Immutable v26.8.15 candidate performance gate

A new process gate builds immutable commit
`816ae65180cc8e8ac6bac76ffcdbc561e93ebb7d` (`v26.8.15`) and the candidate,
uses the same candidate Xray SMUX client and byte-identical server/client
configuration, warms both servers at full 128-stream load, and measures nine
alternating 128 MiB full-duplex rounds for VLESS and Trojan. Linux captures the
server PIDs' RSS, thread, and FD counts and fails above 10% median duration,
64 MiB RSS, 16 threads, or 8 FDs. The non-skippable Linux release script runs
this gate with the existing sing-mux comparison three times.

Three Darwin/arm64 harness runs passed payload integrity and process cleanup.
They are diagnostic only: the latest medians were 2.248 s (`v26.8.15`) versus
2.639 s (candidate), ratio 1.174, for VLESS and 2.608 s versus 3.281 s, ratio
1.258, for Trojan. Earlier runs showed substantial variance, including VLESS
ratios 1.158-1.208 and Trojan ratios 0.962-1.217. Candidate end RSS remained
within 64 MiB of the old server in all runs. Darwin cannot collect the required
thread/FD values for this harness and does not enforce any release budget.
Therefore task 10.4 remains open until the pinned Linux job completes the three
runs and supplies authoritative throughput/latency and resource verdicts.

### SMUX lifecycle hot-path correction

The first immutable candidate comparison exposed a repeatable local SMUX engine
regression before the authoritative Linux release run. Five isolated two-second
samples showed the candidate stream lifecycle at a 6.06 us median, 2,370 B/op,
and 29 allocations versus immutable `v26.8.15` at 5.73 us, 2,338 B/op, and 28
allocations. CPU profiles were saved under `/tmp/xray-smux-profiles`. Compiler
escape output identified the ordinary `Session.OpenStream` accounting callback
closure as the extra allocation. A RED allocation regression fixed the budget
at 28.

The direct `OpenStream` path now publishes without constructing the
transactional callback; `OpenStreamWithAccounting` retains the atomic pool
pending-to-active handoff and both paths share post-publication submission and
ownership checks. Five isolated post-fix samples had a 5.89 us lifecycle median,
2,338 B/op, and 28 allocations versus `v26.8.15` at 5.60 us, 2,338 B/op, and 28
allocations. Round-trip and concurrent round-trip medians were also within the
same local noise band. The full affected `common/singmux/internal/mplsmux`,
`common/singmux`, and `common/mux` package sets passed normally, under race, and
under checkptr. Transactional accounting and accepted/unaccepted failure tests
passed 100 race repetitions. Allocation tests detect checkptr compiler metadata
and skip only allocation measurement under instrumentation; functional checkptr
coverage remains active. Post-optimization process validation passed all 40 SMUX
and all 40 H2MUX Xray/sing-box/Mihomo cells plus direct, legacy Mux, XUDP, RVS,
and WireGuard `v26.8.15` version-skew matrices.

A Docker Desktop linux/amd64 Go 1.26.5 diagnostic run validated Linux RSS,
thread, and FD collection but is emulated, not native release evidence. It
showed VLESS ratio 1.093 and Trojan ratio 1.134, and exposed transient old-server
FD growth from 139 to 267 while the candidate stayed at 139. The gate now stops
both clients before comparing quiescent server resources and separately fails
if either server grows by more than eight FDs under load. Performance budgets
are enforced only when `XRAY_NATIVE_LINUX_RELEASE=1`; Linux release mode itself
fails unless that marker is present, and only the pinned Ubuntu release job sets
it. Task 10.4 remains open pending three native Linux runs.

All release-workflow action references are now pinned to immutable commits and
setup-go caching is disabled, resolving the workflow supply-chain and cache
poisoning findings without broadening job permissions.

### OpenSpec requirement audit and mixed-path soak correction

The task 10.6 audit reviewed all 53 normative scenarios and all 79 tasks against
the authoritative unit/race/checkptr tests, source-removal audit, real process
interop and version-skew results, release wiring, and retained artifact records.
The detailed matrix is recorded in
`openspec/changes/structural-online-presence/evidence/requirements-audit.md`.
After the task 10.1 correction loop, 72 tasks are complete and seven remain
deliberately open: native pinned-Linux gates 10.3-10.4 and release tasks
11.1-11.5. No pending Linux or publication condition is classified as green.

The audit found that the original 30-minute loop repeated only in-process owner
stress and therefore did not satisfy the specified mixed-path soak. A release
contract regression first failed on the missing real-process commands. The Linux
loop now runs the full real SMUX/H2MUX interop matrices and all five direct,
legacy Mux, XUDP, RVS, and WireGuard version-skew matrices on every cycle, in
addition to the exact-owner batches. The contract test, shell syntax, vformat,
source-removal audit, and strict OpenSpec validation pass after the correction.
Native execution remains pending under task 10.3.

### Stale-carrier write/read recovery (2026-08-14)

The first `v26.8.19` release workflow exposed a reconnect race in all three
same-SHA Linux runs. Random VLESS cycles either timed out or reset while the
subsequent cycles recovered. A failed response read waited only for a writer to
publish a replacement stream. If that stale writer returned success instead, it
released the write path without publishing the notification, leaving the reader
blocked until the outer request deadline.

A deterministic regression now holds the stale writer through the failed read,
then lets it return success. It failed before the fix with `read did not replace
the stale stream after the writer released it`. Recovery now distinguishes two
events: an early replacement notification lets a reader consume the response
while replay is still writing, and a write permit lets the reader replace the
stale stream when the writer completed without doing so. The focused tests pass
normally, with race instrumentation, and with `-d=checkptr=2`.

A full local hardening run used Go 1.26.5 on Darwin/arm64 from
`e3502fd7` plus the dirty retry fix:

```sh
TMPDIR=/tmp XRAY_SMUX_STRESS_CYCLES=50 \
  go test -timeout=45m -tags "integration stress" ./common/singmux \
  -run "^TestSMUXProcessStressAndReconnect$" -count=1 -v
```

All 400/400 cycles passed across the eight Xray, sing-box, and Mihomo
direction/carrier topologies in 2569.47 seconds. This proves the local reconnect
harness and payload path; Darwin is not native Linux runtime evidence. The
manual pinned-Linux pre-release workflow remains the authoritative release gate.

### Logical-stream half-close compatibility (2026-08-25)

SMUX v1 does not provide TCP-style logical-stream half-close. Its command 1 is
the only stream-close frame. Xray's embedded engine and the mandatory sing-box
and Mihomo peers terminate both logical directions after receiving it, while
still delivering data buffered before the frame. The upstream sing-mux
`cmdFIN` receive path closes `chFinEvent`, which unblocks both readers and
writers with EOF; its local `Close` also removes the stream after sending FIN.

A temporary Xray-only prototype added `CloseWrite` and passed an isolated
VLESS/TLS and VLESS/REALITY response-after-upload-EOF scenario. It was rejected
because a real external matrix failed all eight tested cells: sing-box and
Mihomo, Xray-client and Xray-server directions, with padding disabled and
enabled, each returned EOF before the complete response. The prototype also
regressed the ordinary 40-cell SMUX interoperability matrix. All incompatible
production changes were removed.

The retained characterization test locks the interoperable behavior: buffered
data precedes EOF, a write after peer close returns EOF, and a sibling stream
on the same session remains usable. The ordinary Xray/sing-box/Mihomo matrix
then passed all 40/40 cells with both padding modes. Tests ran through a service
guard; the working NetBird PID 1382 and Mihomo PID 1931 remained active and
unchanged. Supporting true half-close would require an explicitly negotiated
protocol extension and matching sing-box/Mihomo implementations; reusing
command 1 would break interoperability.


### Negotiated logical half-close extension (2026-08-25)

The compatibility finding above remains true for unextended SMUX v1. Xray now
offers an opt-in carrier version 2 handshake and negotiated command 4 for
directional write-close. `logicalHalfClose` defaults to `off`; `auto` probes on
one carrier and reconnects with byte-identical v0/v1 framing for legacy peers;
`require` fails closed. Command 1 remains full logical close.

The guarded process gate ran five repetitions of Xray/Xray TLS and REALITY with
padding disabled/enabled, plus automatic fallback to real sing-box and Mihomo.
All negotiated and fallback cells passed in 21.087 seconds package time. The
ordinary 40-cell Xray/sing-box/Mihomo SMUX matrix remained green. Unit, race,
H2MUX, and legacy full-close characterization gates also passed. This is
correctness evidence only; no throughput improvement is claimed.

### Previous-release candidate performance oracle (2026-08-25)

The mandatory 10% SMUX duration budget now compares the candidate server with
the previous published fork release `v26.8.25-1457`
(`b7bdfb03fa582cd691197593cc853f6ea209d04f`). The external sing-mux VLESS
comparison remains in the Linux release script as a diagnostic measurement
because last-green `87f58be1` already exceeded that 10% peer ratio on native
Linux (1.153 / 1.095 / 1.215). Replacing that broken oracle is not a budget
relaxation.

Three native Linux `XRAY_NATIVE_LINUX_RELEASE=1` samples of the previous-release
gate produced VLESS ratios 1.001, 1.001, and 1.025. The same host's comparison
against immutable `v26.8.15` mixed 1.07-1.09 and is no longer the release
budget. Resource ceilings stay 64 MiB RSS, 16 threads, and 8 quiescent file
descriptors versus the previous release. Loaded server FDs may include pooled
carriers; the hard loaded ceiling is 128, one per concurrent stream. A
start-to-end self-delta is not used because warmup teardown made that check
flake (CI count 3 saw 21->44 then drained to 9).

## Xray-server-only audit (2026-09-04)

Production changes are in `502fc09c`; the server-only topology contract is in
`06869bda`. This pass also fixes VCS stamping when the comparison builds an
archived source tree. Go 1.27.0, native Linux/amd64, kernel
`7.1.9-200.fc44.x86_64`, schedutil governor, shared development host. No release
capacity or speed improvement is claimed. Commands, raw-log locations, PR
scope, failure history and artifact identities are in the
[audit report](../../docs/audits/2026-09-04-fork-audit.md).

Five isolated 32 KiB round-trip samples before/after the timeout-channel fix:

| Metric | Original `8a9acbd5` | Candidate |
|---|---:|---:|
| Median ns/op | 19864 | 21117 |
| Observed ns/op range | 18985–20573 | 19165–21734 |
| B/op | 6 | 6 |
| allocs/op | 0 | 0 |

Command: compile the original primitive with a Go source overlay and the
candidate without it; run each test binary with
`-test.run '^$' -test.bench '^BenchmarkStreamRoundTrip32KiB$' -test.benchmem
-test.count=5 -test.benchtime=500ms`. Ranges overlap; the result supports no
speedup claim. Timed-out CloseWrite completion channels are retired just as
ordinary Write channels already were, preserving sibling progress without
changing wire bytes or the successful-write allocation path.

All process comparisons used Xray servers and an identical Xray client,
`go build -trimpath -buildvcs=false`, full warm-up, nine alternating samples per
carrier, and active Linux budget assertions. No other agent builds or load ran
concurrently with measurement.

| Xray baseline | Carrier | Baseline median ms | Candidate median ms | Ratio |
|---|---|---:|---:|---:|
| `v26.8.25-1457` | VLESS | 1031.456 | 1018.805 | 0.988 |
| `v26.8.25-1457` | Trojan | 1129.653 | 1126.488 | 0.997 |
| pre-audit main `8a9acbd5` | VLESS | 1227.690 | 1122.868 | 0.915 |
| pre-audit main `8a9acbd5` | Trojan | 1384.387 | 1468.100 | 1.060 |

`TestCandidatePerformanceAgainstPreviousRelease` passed the 10% duration and
RSS/thread/FD limits for both carriers. A diagnostic overlay changing only its
baseline revision and label to `8a9acbd5` also passed. Shared-host variance was
large; these observations do not replace the pinned Linux release environment.

The current functional matrices passed 24/24 SMUX, 24/24 H2MUX and 36/36 VLESS
TCP cells, all with Xray as server. The server-only three-cycle stress passed
18/18 cycles. Historical mixed-role stress/hardening failures remain recorded
in the audit report; they were not retried or erased to manufacture success.

The revised 50-cycle profile passed 300/300 cycles in 1654.378s: three clients
against Xray × VLESS/Trojan × 50. Both the 18-cycle peak profile and the 300-cycle
profile reported zero loopback error/drop/CRC/carrier/collision deltas and no
skipped cells. These results follow the server-only contract and corrected
Mihomo startup barrier. Earlier failed mixed-role runs remain explicit in the
audit; this is not a claim that all historical reconnect failures were fixed.

## TCP Brutal v2 locked destination rules (2026-09-05)

Source: `5eb02c2016fe2a25054916ea4644855d4ca84f0d` plus the local Brutal
compatibility patch. Native host: Linux `7.1.9-200.fc44.x86_64`, amd64,
AMD Ryzen 7 4800H, `schedutil` governor, Go 1.27.0. This shared development
host is not the pinned release performance environment.

A locked system rule now takes precedence when socket configuration returns
`EPERM` and a read on the same descriptor confirms `TCP_CONGESTION=brutal`.
A rejected algorithm change is not followed by a rate write. Other errors
remain fatal. The control exchange and advertised receive ceiling are
unchanged. This is a compatibility fix, not a throughput optimization.

The original implementation failed the two targeted locked-setting tests
with `operation not permitted`. The candidate passes those tests, rejected
algorithm/read-error cases, a real kernel TCP congestion read, invalid
response layouts, and the existing Brutal suite. Negative-control overlays
that accepted another algorithm or invalid response layouts were rejected by
the new tests. The dependency guard remains unchanged and passes; the Linux
read uses the existing standard-library syscall approach with a bounded
16-byte buffer and validated length/termination.

Native unit, race, checkptr and vet commands from `TESTING.md` passed for the
applicable SMUX packages and callers. The 24-cell Xray-server interoperability
matrix passed with Xray, sing-box and Mihomo clients. Fifty package repetitions
passed; embedded engine coverage was 87.3%. The three-cycle peak stress profile
passed 18/18 cycles in 95.489 s, with zero checked loopback error/drop/CRC/
carrier/collision deltas. Initial validation exposed the package's prohibition
on a direct `x/sys/unix` import and missing geodata fixtures. The import was
removed without changing the guard, and the existing local `geoip.dat` and
`geosite.dat` fixtures were supplied before the successful package run.

### Real module regression

TCP Brutal v2.0.0 source at
`04e4dc7ae13a4852f0bfe0c8d353e621e429e22e` was built outside the repository and
loaded only in a QEMU 10.2.2 TCG guest, using the same Linux kernel version,
2 virtual CPUs, 1536 MiB RAM, and no guest network interface. The host's kernel
modules, services and networking were not changed. The module build reported
GCC 16.2.1 versus kernel GCC 16.1.1 and omitted BTF because `vmlinux` was absent;
the resulting module loaded and reported version 2.0.0.

The checkptr-enabled tests were compiled with:

```sh
CGO_ENABLED=0 go test -c -tags 'integration brutalkernel' \
  -gcflags=all=-d=checkptr=2 -o brutal-kernel.test ./common/singmux
```

Inside the guest, both `TestBrutalKernelSocketPolicy` and
`TestBrutalKernelSMUXProcess` passed in all three modes documented in
`TESTING.md`: application settings without a rule, a locked route plus locked
rule, and an unlocked route plus locked rule. The process test used a real
Xray server and Xray client with SMUX Brutal enabled and checked the complete
SOCKS-to-server-to-echo path. The original Xray binary failed that path under
the locked route with `Brutal socket control failed`; the candidate passed.
The system rule retained 12,500,000 B/s and group ID 1 instead of the requested
1,000,000 B/s; the application-only case retained group ID zero and applied
1,000,000 B/s. Final rule membership returned to zero after test cleanup.

These are functional kernel-module results, not emulated performance evidence
or a claim about every supported Linux kernel. No passive-classification,
active-probing, or packet-loss throughput claim follows from this check.

Release-style Linux/amd64 artifact, built with `CGO_ENABLED=0`, `GOAMD64=v1`,
`-trimpath`, `-buildvcs=false`, `-gcflags='all=-l=4'`, and
`-ldflags='-X github.com/xtls/xray-core/core.build=5eb02c20-dirty -s -w -buildid='`:
SHA-256 `ccf0ce48b2219c0463ff8382c335548ef7610768d81c89de57fe77cfb8fa89d5`.
`file`, `go version -m`, and `xray version` verified a stripped static amd64
binary, Go 1.27.0, and version `26.9.4-2204` with build `5eb02c20-dirty`.

The documented bounded hardening command also passed all 300/300 cycles
(three clients × two carriers × 50) in 1659.635 s:

```sh
XRAY_SMUX_STRESS_CYCLES=50 XRAY_SMUX_STRESS_TCP_STREAMS=16 \
  go test -timeout=45m -tags 'integration stress' ./common/singmux \
  -run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
```

No cells were skipped. Checked loopback errors, drops, CRC errors, carrier
errors, collisions and carrier changes all had zero deltas. The harness's
RSS/thread growth assertions passed.

### Performance regression checks

The previous-release gate used Go 1.27.0, `CGO_ENABLED=0`, identical
`go build -trimpath -buildvcs=false` flags for both server versions, an
identical candidate Xray client, full warm-up, and nine alternating samples
per carrier. Three repetitions passed with Linux duration/RSS/thread/FD
budget assertions enabled (`XRAY_NATIVE_LINUX_RELEASE=1`). Other builds,
race tests, stress tests, microbenchmarks and QEMU runs had finished before
the timed comparisons. This enables the assertions on the shared native host;
it does not turn that host into the pinned release environment.

| Run | Carrier | Baseline median ms | Candidate median ms | Ratio |
| --- | --- | ---: | ---: | ---: |
| 1 | VLESS | 883.810 | 874.381 | 0.989 |
| 1 | Trojan | 1069.955 | 1054.136 | 0.985 |
| 2 | VLESS | 875.232 | 876.657 | 1.002 |
| 2 | Trojan | 1091.032 | 1096.105 | 1.005 |
| 3 | VLESS | 882.083 | 875.803 | 0.993 |
| 3 | Trojan | 1062.822 | 1055.900 | 0.993 |

The baseline is `v26.8.25-1457`
(`b7bdfb03fa582cd691197593cc853f6ea209d04f`). The precompiled equivalent of
`go test -tags 'integration stress performance' ./common/singmux
-run '^TestCandidatePerformanceAgainstPreviousRelease$' -count=3 -v`
was used, with the matching-flags candidate binary supplied via
`XRAY_E2E_BIN`. Ratios stay within the 10% budget and support no speedup claim.
These ordinary SMUX comparisons do not exercise Brutal pacing.

The precompiled `BenchmarkStreamRoundTrip32KiB` was then run with
`-test.run '^$' -test.bench '^BenchmarkStreamRoundTrip32KiB$' -test.benchmem
-test.count=5`: 26847, 27704, 27710, 27735 and 26662 ns/op. Median was
27704 ns/op; all samples reported 0 allocs/op (amortized B/op: 3, 4, 6, 3, 1).
This preserves the allocation gate, not evidence of a local speed improvement.

### TCP counter attribution

Host interface error/drop/FIFO/frame/carrier/collision counters had zero
deltas during the comparison. Global host TCP counters did increase
(`RetransSegs=40464`, `OutRsts=15265`, `AttemptFails=15234`), so they were not
reported as clean network evidence or attributed solely to Xray.

A separate diagnostic repetition ran in a fresh user/network namespace with
only its own loopback, recording TCP counters around each baseline/candidate
sample through a temporary test overlay. It passed the same performance and
resource assertions. Across the complete isolated run, `RetransSegs=7635`,
`DelayedACKLost=7635` and `TCPLossProbes=7640`; drop and timeout counters did
not increase. Timed samples showed no connection resets or failed opens.
Their retransmit/loss-probe totals were:

| Carrier/server | RetransSegs | TCPLossProbes |
| --- | ---: | ---: |
| VLESS baseline | 1592 | 1594 |
| VLESS candidate | 1727 | 1727 |
| Trojan baseline | 1742 | 1742 |
| Trojan candidate | 1713 | 1714 |

The retransmits track the kernel's tail-loss probes in both versions rather
than interface drops. Outside measured transfer samples, the fixture recorded
8 failed connection attempts and 2 established resets (`TCPAbortOnData=2`),
accounting for its 10 outgoing resets during startup/teardown. Original global
host deltas remain unscoped; the isolated diagnostic supplies the attributable
TCP evidence without changing the host's networking. No packet-loss capacity
or camouflage claim is made.

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

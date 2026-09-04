# Sing-mux release gates

## Server topology

Xray is the only proxy server in these gates. Xray, sing-box, and Mihomo are
clients of that server. Baseline/candidate performance runs compare Xray server
versions. Reverse-role cells and external proxy-server performance comparisons
are excluded by the repository rule in `AGENTS.md`. Local echo and REALITY cover
fixtures remain supporting test services.

## Negotiated logical half-close

The default remains legacy full-close. The negotiated gate covers Xray/Xray over
TLS and REALITY with padding off/on, plus `auto` fallback from an Xray client
to a pinned Xray server version predating SMUX half-close negotiation. Every command is wrapped by the NetBird/Mihomo service guard.

```sh
GOTOOLCHAIN=auto go test ./common/singmux/internal/mplsmux \
  -run 'Test(NegotiatedHalfClose|CloseFrameTerminatesLogicalStream)' -count=100
GOTOOLCHAIN=auto go test -tags integration ./common/singmux \
  -run 'TestSMUX(NegotiatedHalfCloseProcessMatrix|AutoFallbackLegacyXray)' -count=5 -v
```

## Logical-stream close semantics

SMUX v1 command 1 is a full logical-stream close in Xray, sing-box, and Mihomo;
it is not a TCP-style half-close. A peer close drains buffered data before EOF,
rejects writes in the opposite direction, and leaves sibling streams on the
carrier usable. Keep this compatibility gate when changing stream lifecycle:

```sh
GOTOOLCHAIN=auto go test ./common/singmux/internal/mplsmux \
  -run '^TestCloseFrameTerminatesLogicalStream$' -count=100 -v
```

The recorded reference point is in [`BASELINE.md`](BASELINE.md). These gates
cover the in-tree SMUX v1 and H2MUX stacks. YAMUX remains outside the scope.

The default suite covers the wire codec, padding, pool behavior, TCP and UDP
adapters, Xray integration, the MPL SMUX engine, and the recursive external-mux
dependency ban. The engine package is held above 80% statement coverage.

The canonical release entrypoint is `testing/release/structural_presence.sh`.
`standard` runs format, vet, repository-wide unit/race/checkptr, interop,
version-skew, and aggregate lifecycle gates. `linux` additionally runs the
non-skippable pinned Linux/amd64 50-cycle reconnect stress, nine-round
performance comparison, real `yt` environment contract, 30-minute structural
soak, and release artifact inspection. The manual
`.github/workflows/pre-release-validation.yml` workflow runs this gate before
tagging. `.github/workflows/release.yml` is intentionally build-only so publishing
a release never starts a duplicate soak. A missing Linux capability or environment
value in pre-release validation is a failure, not a skip.

```sh
testing/release/structural_presence.sh standard
XRAY_E2E_YT_INTERFACE=yt XRAY_E2E_YT_IPV6=fd00:7872:6179::1 \
  XRAY_STRUCTURAL_SOAK_SECONDS=1800 XRAY_NATIVE_LINUX_RELEASE=1 \
  testing/release/structural_presence.sh linux
```

```sh
go test ./common/singmux/... ./common/mux ./app/proxyman/inbound ./app/proxyman/outbound ./infra/conf
go test -race ./common/singmux/... ./common/mux
go test -gcflags=all=-d=checkptr=2 ./common/singmux ./app/proxyman/inbound
go test -cover ./common/singmux/internal/mplsmux
go test ./common/singmux/... -count=50
go test ./common/singmux/internal/mplsmux -run '^$' -bench '^BenchmarkStreamRoundTrip32KiB$' -benchmem -count=5
```

The focused Brutal server gate covers per-inbound parsing, bounded rate
selection, disabled and malformed control streams, duplicate negotiation,
post-socket-control carrier closure, ordinary SMUX continuation, and H2MUX
carrier-scoped parity:

```sh
go test ./infra/conf ./app/proxyman/inbound -run 'Test(InboundSMuxConfigBuild|ReceiverBrutalOptions)$' -count=1
go test ./common/singmux -run '^(TestServerBrutal|TestServiceBrutal|TestServiceH2MuxBrutal)' -count=1
```

The 32 KiB hot-path allocation gate is zero allocations per round trip and is
compiled only without `-race`, because race instrumentation changes allocation
behavior. Frame, padding, and outer-protocol decoders also have Go fuzz targets.

The functional process suites build and start Xray, sing-box, and Mihomo. They
run Xray, sing-box, and Mihomo clients against the Xray server for VLESS and
Trojan, TCP and UDP, with padding disabled and enabled (24 scenarios per mux
protocol).

```sh
go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
go test -tags integration ./common/singmux -run '^TestH2MUXProcessInteropMatrix$' -count=1 -v
```

The separate VLESS TCP server gate keeps SMUX out of the topology and covers
the complete TLS/REALITY and no-flow/Vision matrix against all three clients
(12 scenarios). Sing-box is built with uTLS for REALITY. Mihomo readiness is
confirmed by a full SOCKS-to-echo probe instead of accepting an open local
SOCKS port as proof that its provider has finished starting.

```sh
go test -tags integration ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -v
```

The matching connection-latency benchmark keeps one Xray client and server
process alive per mode and opens a new VLESS connection for every operation.
Use a fixed iteration count on macOS: adaptive multi-second runs can exhaust
its ephemeral port range before TIME_WAIT entries expire.

```sh
go test -tags integration ./common/singmux -run '^$' \
  -bench '^BenchmarkVLESSTCPProcess$' -benchtime=50x -count=5
```

## RemnaNode production configuration gate

The RemnaNode gate keeps a sanitized contract copy of the deployment
configuration and runs its behavior through real processes. Secrets are
replaced by the repository test REALITY key pair and RemnaWave's empty client
list is populated with generated test users. VLESS no-flow is represented by
an empty string: the literal value `none` is invalid and has a separate
negative regression test.

```sh
go test -tags integration ./common/singmux \
  -run '^(TestRemnaNodeProductionConfigContract|TestRemnaNodeConfigRejectsLiteralNoneFlow|TestRemnaNodeConfigProcessE2E)$' \
  -count=1 -v
```

The process test builds and starts Xray, sing-box, and Mihomo clients against
the Xray server. Each client is exercised both directly and over SMUX. The
runtime assertions cover VLESS REALITY no-flow, the Unix REALITY target and
PROXY protocol v2, HTTP and TLS sniffing, route-only disabled, VLESS route 50,
the mobile-user block, private-IP block, TCP port 25 block, UDP port 443 block,
DNS outbound routing, four-server fallback, successful-response caching,
`UseIP`, `ForceIPv4`, `ForceIPv6`, TCP Fast Open configuration, and legacy
access/error file creation and route tags.

The exact production endpoints cannot be used in a deterministic test. The
process fixture therefore substitutes local DoH and TCP DNS servers, uses
temporary ports and a temporary Unix socket, and binds the server to loopback.
`TestRemnaNodeProductionConfigContract` separately checks the exact DNS URLs,
ports 443/8443, `0.0.0.0`, `/dev/shm/nginx.sock`, interface `yt`, log paths,
outbound ordering, and all seven routing rules before building the complete
configuration. The two freedom outbounds use a test-only allow final rule in
the process fixture so Xray can reach isolated loopback targets; the contract
test proves that this override is absent from production settings.

The `TORRENT` outbound is present but no routing rule selects it. The contract
test deliberately records it as unreachable; it must not be described as
runtime-covered until a torrent rule and its E2E assertion are added.

The Linux production-interface gate needs an isolated `yt` interface with a
locally assigned IPv6 address. For example, in a disposable network namespace
or CI runner with `CAP_NET_ADMIN`:

```sh
ip link add yt type dummy
ip link set yt up
ip -6 address add fd00:7872:6179::1/128 dev yt

XRAY_E2E_YT_INTERFACE=yt \
XRAY_E2E_YT_IPV6=fd00:7872:6179::1 \
go test -tags 'integration remnanode_release' ./common/singmux \
  -run '^(TestRemnaNodeLinuxReleaseEnvironment|TestRemnaNodeProductionConfigContract|TestRemnaNodeConfigRejectsLiteralNoneFlow|TestRemnaNodeConfigProcessE2E)$' \
  -count=1 -v

ip link delete yt
```

The release-tagged test fails unless the interface is literally named `yt`
and the selected IPv6 address is assigned to it. The process E2E then binds
the IPv6 target to that address and forces the YT outbound through `yt`.

### Xray server memory-pressure profile

The memory-pressure gate measures only the Xray server process. Four local
Xray clients are unmeasured traffic generators; their access logs are disabled
and their resource use must not be reported as server capacity. The server is
started with the deterministic RemnaNode configuration above. The only added
server field is a loopback `metrics.listen` endpoint, and a regression test
proves that removing this field restores the original process fixture.

The SMUX profile opens VLESS/REALITY streams through the
`reality-pro-de-mux` inbound. The direct profile removes both `smux` and `mux`
from every generator and alternates physical VLESS/REALITY connections between
the `reality-pro-de-mux` and `reality-pro-de` inbounds. Every request carries
`www.google.com` as its VLESS destination, so the existing `vlessRoute: 50`
rule selects `DIRECT` without a test-only routing rule or outbound. Local sinks
deliberately stop reading. This applies backpressure while connections remain
live. The loop samples RSS from the Xray server PID after every 64-connection
wave and stops only when it reaches the requested target, the process or a
connection fails, or a wave produces no measurable RSS growth. It does not
retry failed connections.

The default target is 5 GiB. Run it only on a disposable Linux/amd64 host with
enough memory, file descriptors, and disk space for the server, generators,
test process, and profiles:

```sh
mkdir -p /tmp/xray-remnanode-profiles

XRAY_REMNANODE_MEMORY_PROFILE=1 \
XRAY_REMNANODE_PROFILE_DIR=/tmp/xray-remnanode-profiles \
go test -tags 'integration stress' ./common/singmux \
  -run '^TestRemnaNodeServerMemoryProfile$' -count=1 -v
```

Use the direct mode when profiling the ordinary non-multiplexed server path:

```sh
XRAY_REMNANODE_DIRECT_MEMORY_PROFILE=1 \
XRAY_REMNANODE_PROFILE_DIR=/tmp/xray-remnanode-direct-profiles \
go test -tags 'integration stress' ./common/singmux \
  -run '^TestRemnaNodeDirectServerMemoryProfile$' -count=1 -v
```

`XRAY_REMNANODE_MEMORY_TARGET_BYTES` changes the target for a diagnostic run.
The gate writes `heap.pb.gz`, `allocs.pb.gz`, `goroutine.pb.gz`, and
`vars.json` from the server metrics endpoint. On Linux it also fails on a
positive loopback error/drop/CRC/carrier/collision/link-change delta. A Darwin
run validates the harness only; it is not Linux server-capacity evidence.

The stress suite runs six client/carrier topologies against Xray. Xray and
sing-box clients run three cycles with 128 concurrent full-duplex TCP streams;
Mihomo clients use 32. Every stream carries 1 MiB in each direction, and
every cycle sends 10,000 UDP datagrams across four destinations. The server is
killed and restarted between cycles while the client remains running. After
each start, the harness waits for an available process-ready marker and requires
a complete SOCKS-to-server-to-echo exchange before beginning the measured load;
an open TCP or SOCKS port alone is not readiness evidence.

Xray and sing-box peak stress keep all 128 streams on one carrier. Mihomo stress caps
each cycle at 32 streams and allows up to four carriers to avoid turning the
peer's capacity into the bottleneck; datagram and restart load is unchanged.
The ordinary SMUX/H2MUX matrices retain cold single-carrier Mihomo coverage.

```sh
go test -tags 'integration stress' ./common/singmux -run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
```

The release gate first runs the three-cycle peak profile,
then raises all six Xray-server topologies (three clients × two carriers) to
50 cycles with bounded per-cycle concurrency:

```sh
XRAY_SMUX_STRESS_CYCLES=50 XRAY_SMUX_STRESS_TCP_STREAMS=16 go test -timeout=45m -tags 'integration stress' ./common/singmux -run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
```

The hardening gate uses 16 TCP streams per cycle to keep GitHub runner
scheduling bounded across 49 between-cycle restarts.
`TestClientRetrySkipsResetCarrierForHealthyPooledSibling` pins that a
pre-response reset evicts its failed owner before replay. A healthy pooled
sibling is reused without exceeding the configured carrier cap. If every
remaining sibling also resets, replay continues up to `maxConnections`
times and then dials a new carrier.
That is 800 one-MiB stream
runs per topology, versus 384 for ordinary Xray/sing-box peak stress and 96 for
ordinary Mihomo peak stress; UDP load remains 10,000 datagrams per cycle.

On Linux, the stress test also captures a historical baseline and delta for the
loopback interface error, drop, CRC, carrier, collision, and carrier-change
counters. It never clears counters and fails if any checked counter increases.
Process RSS and thread counts are sampled after each cycle to detect linear
growth.

The hard Linux release budget is the previous published fork release. It uses a
full-load warm-up and nine alternating rounds with access logging disabled, and
fails above a 10% median full-duplex regression.

```sh
go test -tags 'integration stress performance' ./common/singmux \
  -run '^TestCandidatePerformanceAgainstPreviousRelease$' \
  -count=3 -v
```

`TestCandidatePerformanceAgainstPreviousRelease` builds immutable
`v26.8.25-1457` (`b7bdfb03fa582cd691197593cc853f6ea209d04f`) and the
candidate, keeps an identical candidate Xray SMUX client on both sides, warms
both servers, and measures nine alternating full-duplex rounds. On Linux it
fails above 10% median duration regression, 64 MiB RSS, 16 threads, or 8
quiescent file descriptors versus the previous release. Under load it also
fails if either server holds more file descriptors than the 128 concurrent
streams, which would mean the mux is no longer sharing carriers. Other hosts
record diagnostics only and cannot satisfy the release gate.

`XRAY_E2E_BIN`, `SING_BOX_E2E_BIN`, and `MIHOMO_E2E_BIN` may point to existing
binaries. `XRAY_SMUX_STRESS_CYCLES` controls reconnect cycles.
`XRAY_SMUX_STRESS_TCP_STREAMS` may reduce TCP concurrency for a diagnostic run;
the release gate fixes it to 16 only for the cumulative 50-cycle profile after
the ordinary 128-stream peak profile passes.

The production path contains no vendored SMUX/YAMUX/H2MUX implementation and
does not import Sagernet, Metacubex, Hashicorp, or another mux library. The
embedded SMUX engine is maintained in this tree under MPL-2.0.

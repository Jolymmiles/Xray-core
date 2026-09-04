# Fork audit — 2026-09-04

## Starting state

The clean audit worktree started at `8a9acbd5c7c6d635ad0bc879f4e6c2d24e27d2f3`, equal to fetched `origin/main`. It contains fetched `upstream/main` (`cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47`) with no missing upstream commits. The fork delta contains 226 commits and 454 files: 178 Go production/tool files, 223 Go test files, seven generated files, and 46 documentation/configuration/script files.

GitHub issues are disabled in Jolymmiles/Xray-core. The two initially open PRs were [#5](https://github.com/Jolymmiles/Xray-core/pull/5) and draft [#8](https://github.com/Jolymmiles/Xray-core/pull/8). PR #9 was already merged. Existing main CI was green at the starting commit.

The review combined the fork diff, package contracts/callers, two independent review axes, and execution of the repository suite. Source inspection concentrated on modified server/protocol, resource ownership, concurrency, configuration and release paths. This is not a claim that every line of the 67,244 added lines received an independent security audit.

## Confirmed main fixes

| Files | Reproduced problem and result |
|---|---|
| `app/reverse/portal.go`, `portal_internal_test.go` | Closing a PortalWorker waited for its periodic heartbeat before unblocking the heartbeat writer. The regression now starts the actual Periodic callback; shutdown closes I/O before joining. |
| `app/proxyman/inbound/worker.go`, `lifecycle_test.go` | UDP shutdown held the mutex required by an admitted cleanup callback while joining it. Shutdown releases that mutex before joining the checker. |
| `common/singmux/internal/mplsmux/stream.go`, `session_test.go` | Two timed-out half-closes reused one completion channel, blocking carrier progress and sibling streams. A timeout retires its result channel, matching the existing Write contract. |
| `transport/internet/finalmask/xdns/client.go`, `resolver_progress_test.go` | Resolver selection repeatedly examined the same busy next resolver forever. Selection advances through the ring and preserves the current resolver when all alternatives are busy. |
| `proxy/vless/validator.go`, `validator_concurrent_mutation_test.go` | Concurrent Add/Del could publish a negative user count and panic while constructing a snapshot. Mutations are serialized; handshake lookup remains unchanged. |
| `transport/internet/tls/resumption.go`, `resumption_lifetime_test.go` | A uintptr cache identity did not retain its object, allowing future address reuse to alias another TLS scope. A comparable pointer-backed cache interface now retains identity until LRU eviction. |
| `proxy/hysteria/client.go`, `server.go`, `address_lifetime_test.go` | Destinations escaped pooled request/reader storage and changed after release or subsequent reads. Addresses now own their lifetime at the dispatch boundary. Obsolete pooled-address fields/types were removed; zero-allocation parser tests remain unchanged. |
| `common/singbridge/packet.go`, `packet_test.go` | Cached UDP reads raced Close, late buffers leaked, EOF was swallowed, pooled addresses were read after release, and undersized outputs silently truncated packets. The adapter synchronizes ownership, drains buffered payloads before terminal errors, converts addresses while valid, and reports short buffers. This implements the root-cause portion of PR #5. |
| `common/singmux/stress_integration_test.go` | Failure diagnostics retained the original server's logs after a restart. The cleanup now reads the current topology server. This changes diagnostics only. |

Each production root cause was reproduced on the original implementation and verified after the fix. New tests check behavior, including concurrent close, retained values, error propagation and sibling progress. No protocol bytes, authentication rules, dependencies, generated protobufs or allocation-test budgets were changed. General panic recovery and the unrelated access-log rewrite from PR #5 were not adopted.

## Open PR dispositions

PR #5 identifies a valid cached-buffer race. Its published patch also adds broad panic containment and unrelated logging changes. The focused main fix addresses the reproduced cause and adds stronger release/error/payload assertions. The existing four inline comments were reviewed; the published PR is not automatically considered resolved by a local follow-up branch.

PR #8 introduces an unmerged MTProxy feature. Its confirmed configuration, source-cache, cancellation, fallback, secret-generation and Middle-End lifecycle defects are fixed separately against its own branch. The apparent Go timer deadlock was not supported by the inspected Go 1.27 timer semantics. Timestamp rollover in 2106 and ambiguous DD/TLS prefix rules were not treated as established present-day interoperability blockers.

MTProxy's existing tests named Process are in-process Handler fixtures, not Xray subprocess/HandlerService E2E. The follow-up corrects that documentation. Real subprocess management/fallback coverage and official Telegram Desktop/Android DD/EE interoperability remain merge gates for the feature.

## Verification conditions

Linux/amd64, Go 1.27.0, kernel `7.1.9-200.fc44.x86_64`, CPU governor `schedutil`. Measurements use this shared development host, not the pinned release host. No performance improvement or release capacity is claimed. Interop clients are the repository-pinned sing-box `46f00de9aa060ab989353953051268c7c4745664` and Mihomo `2e1394a7cf4c2d25ac6290a05ee0e21f786073de`.

Initial setup exposed the system Go 1.26.7/GOTOOLCHAIN=local mismatch; checks used the installed Go 1.27.0. The initial full suite lacked geodata assets; existing assets were copied from the canonical worktree into ignored resources/. A long build-temp path exceeded Linux UNIX socket path limits; those packages passed after using a short temporary path. These setup failures are retained in the local evidence rather than described as test successes.

## Current server-only contract

The maintainer narrowed process validation during this audit: each topology has
one Xray proxy server, with Xray, sing-box or Mihomo as client. The rule is in
`AGENTS.md` and `common/singmux/TESTING.md`. Shared runners no longer expose an
external-server direction or external-server configuration helper.

SMUX and H2MUX each have 24 cells (three clients, two carriers, TCP/UDP, padding
off/on). Stress has six client/carrier topologies. Performance compares Xray
server versions. Auto fallback uses pinned legacy Xray
`d8a67242bb255b23ddc92338ac8bc98d66b45088`; a negative require-mode control verifies
that the fixture cannot negotiate half-close before testing successful auto mode.

Mihomo client startup now waits for its post-up marker after ApplyConfig, then
SOCKS readiness and the full echo-path assertion. The old parse-complete log
preceded OnRunning and could expose a listener which rejected initial traffic.
This shared barrier is used by mux, VLESS, Hysteria, TLS-profile and RemnaNode
process tests. Failure retries and artificial readiness delays were not added.

The external-server performance test was removed from the release script. The
historical-Xray build helpers disable VCS stamping for source archives without
.git metadata; both performance versions use matching build flags.

## Executed checks

Commands used Go 1.27.0. `XRAY_E2E_BIN`, `SING_BOX_E2E_BIN`, and
`MIHOMO_E2E_BIN` pointed at the actual built binaries. Short temporary paths
avoid Linux UNIX socket path limits. Logs are retained locally under
`/tmp/xray-audit/`; they are not repository artifacts.

```sh
go test ./... -count=1 -timeout 20m
go test ./transport/internet ./transport/internet/splithttp -count=1
go test -race ./transport/internet/reality ./transport/internet/tls \
  ./transport/internet/finalmask/xdns ./proxy ./proxy/vless/... \
  ./proxy/hysteria ./proxy/shadowsocks_2022 ./common/singbridge \
  ./common/singmux/... ./common/mux ./app/reverse \
  ./app/proxyman/inbound ./app/proxyman/outbound -count=1
go test -gcflags=all=-d=checkptr=2 ./transport/internet/reality \
  ./transport/internet/tls ./transport/internet/finalmask/xdns \
  ./proxy ./proxy/vless/... ./proxy/hysteria ./common/singbridge \
  ./common/singmux/... ./common/mux ./app/reverse ./app/proxyman/inbound -count=1
go vet ./...
go vet -tags integration,stress,performance ./common/singmux ./testing/release
go test -cover ./common/singmux/internal/mplsmux -count=1
go test -tags integration ./common/singmux \
  -run '^Test(SMUXProcessInteropMatrix|H2MUXProcessInteropMatrix|HysteriaProcessClientMatrix|VLESSTLSX25519ProcessMatrix)$' -count=1 -v
go test -tags integration ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -v
go test -tags integration ./common/singmux \
  -run '^TestSMUX(NegotiatedHalfCloseProcessMatrix|AutoFallbackLegacyXray)$' -count=5 -v
go test -tags integration ./common/singmux -run '^TestRemnaNodeConfigProcessE2E$' -count=1 -v
go test -tags integration ./testing/scenarios -run '^TestReverseVersionSkew$' -count=1 -v
```

Affected unit/race/checkptr and vet checks passed. Server-only process matrices
passed without skips: VLESS 36/36, SMUX 24/24, H2MUX 24/24; Hysteria,
TLS/X25519, RemnaNode and reverse version-skew also passed. Negotiated half-close
passed 20 cells; legacy-Xray auto fallback passed 10 cells plus 10 negative
require controls. MPL SMUX statement coverage was 87.1%.

The local full suite is **not reported green**: its external Google
REALITY/Chrome case returned EOF. UNIX path failures in that run were followed
by successful checks of both affected packages with short temporary paths.
GitHub full-suite CI passed for code commit `502fc09c` and server-only topology
commit `06869bda`; this separate success does not erase the local failure.

## Performance evidence

Five samples per isolated benchmark; medians below. The before version restores
the original primitive from `8a9acbd5` with a Go overlay. Both test binaries use
the same Go toolchain and flags. Each was run with `-test.run '^$'`, the named
`-test.bench`, `-test.benchmem`, `-test.count=5`, and `-test.benchtime=500ms`.
No builds, race tests, process stress or other agent load ran during measurement.

| Primitive | Before ns/op | After ns/op | Before/after allocations | After B/op |
|---|---:|---:|---:|---:|
| `BenchmarkStreamRoundTrip32KiB` | 19864 | 21117 | 0 / 0 | 6 |
| `BenchmarkUDPReaderServerPacketDestination` | 5.970 | 36.550 | 0 / 1 | 16 |
| `BenchmarkUDPReaderServerPacketDestinationIPv4` | 5.883 | 22.640 | 0 / 1 | 4 |

SMUX timing ranges overlap (18,985–20,573 ns before; 19,165–21,734 ns after).
Hysteria deliberately pays one allocation for an independently owned address;
the old zero-allocation value aliased mutable pooled storage. The parser's
separate zero-allocation budgets remain intact. These results do not establish
a speed improvement.

Process comparisons used `TestCandidatePerformanceAgainstPreviousRelease`, nine
alternating samples per carrier, `XRAY_NATIVE_LINUX_RELEASE=1` to execute the
budget assertions, and matching `go build -trimpath -buildvcs=false` flags.
A second diagnostic run changed only the baseline revision/label via an overlay
to compare directly with the audit's original main. Every proxy server was Xray.

| Xray server baseline | Carrier | Baseline median ms | Candidate median ms | Ratio |
|---|---|---:|---:|---:|
| `v26.8.25-1457` | VLESS | 1031.456 | 1018.805 | 0.988 |
| `v26.8.25-1457` | Trojan | 1129.653 | 1126.488 | 0.997 |
| original main `8a9acbd5` | VLESS | 1227.690 | 1122.868 | 0.915 |
| original main `8a9acbd5` | Trojan | 1384.387 | 1468.100 | 1.060 |

All four comparisons passed the 10% median and RSS/thread/FD budgets. Timing
variance on this shared schedutil host was substantial; these are regression
observations, not a pinned-host capacity or release-performance claim. Initial
archive builds failed on VCS metadata before measurements; the helper fix and
successful later measurements are recorded separately.

## Artifacts and pull requests

Main static Linux/amd64 build:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build \
  -trimpath -buildvcs=false -gcflags=all=-l=4 \
  -ldflags='-X github.com/xtls/xray-core/core.build=audit-8a9acbd5 -s -w -buildid=' \
  -o /tmp/xray-audit/xray-linux-amd64 ./main
file /tmp/xray-audit/xray-linux-amd64
sha256sum /tmp/xray-audit/xray-linux-amd64
go version -m /tmp/xray-audit/xray-linux-amd64
```

Artifact SHA256: `dcba1baa6bd99344a98285314c3b47cb33bcf9e3d7e4b5515dcadab8d0b1558f`.
The binary contains the production fixes subsequently committed as `502fc09c`;
later topology/documentation changes do not enter the production binary.

- [PR #11](https://github.com/Jolymmiles/Xray-core/pull/11): main server fixes,
  server-only test contract, readiness and evidence.
- [PR #10](https://github.com/Jolymmiles/Xray-core/pull/10): separate MTProxy
  follow-up against `feat/mtproxy-inbound-pr`, commit `78532cd1`.

MTProxy unit/config/race/checkptr/vet and 15/15 in-process integration executions
passed, followed by an independent parent regression check and static Linux
build. Its test-build SHA256 is
`fa81bdcf5c63b2b439ca8bc77a99f7b1bc5fe1c89c7ebc4ab974b0eff6fadc8b`.
That artifact records the original PR8 revision plus modified sources; it is not
an official release asset. No PR was merged and no release was published by this
audit. Original unrelated worktrees were left untouched.

## Stress/hardening outcome and remaining limits

The revised Xray-server-only profiles completed successfully:

```sh
go test -tags integration,stress ./common/singmux \
  -run '^TestSMUXProcessStressAndReconnect$' -count=1 -timeout=45m -v
XRAY_SMUX_STRESS_CYCLES=50 XRAY_SMUX_STRESS_TCP_STREAMS=16 \
  go test -tags integration,stress ./common/singmux \
  -run '^TestSMUXProcessStressAndReconnect$' -count=1 -timeout=45m -v
```

Peak: 18/18 cycles. Hardening: 300/300 cycles, 1654.378s, with 50 cycles for
each Xray/sing-box/Mihomo client × VLESS/Trojan combination. Both processes
exited zero; there were no skipped cells. Loopback error/drop/CRC/carrier/
collision counters had zero deltas throughout both profiles. Additional
interface error-counter snapshots, taken shortly after hardening started and
at completion, also had no positive deltas. Global TCP counters include normal
background traffic and intentional connection resets from forced restarts;
they are not evidence of a zero-retransmit production network.

Earlier evidence is retained:

- Original mixed-role peak stress passed 22 of 24 intended cycles and failed
  the first echo after restarting Xray/Trojan with the pinned sing-box client.
  The client reused a dead TCP carrier and returned a handshake broken pipe.
  Source inspection establishes that its first stream-request write has no
  reopen/replay path; exact FIN/RST scheduling was not traced.
- Original mixed-role hardening completed 239 of 400 intended cycles and
  failed five topologies: sing-box→Xray VLESS/Trojan, Xray→Mihomo VLESS/Trojan,
  and initial Mihomo→Xray VLESS readiness. The Mihomo startup barrier defect
  was corrected. The excluded Xray-client/external-server restart failures
  were not assigned a proven root cause or claimed fixed.
- The later server-only gate is a changed contract and harness, not a retry
  of the old gate. Its 300/300 success does not establish that every earlier
  external-client restart failure has been causally eliminated.
- The local full-suite Google/Chrome EOF remains recorded. Fresh GitHub CI
  success is separate evidence. No test retry or sleep was added to conceal it.
- MTProxy still needs real Xray subprocess/HandlerService/fallback E2E and
  official Telegram Desktop/Android DD/EE validation before feature merge.
  These were not replaced by in-process fixtures.

A fresh Linux rebuild after the topology changes was byte-identical to the
reported main artifact. The evidence verifier checked matrix/cycle counts,
exit-status records, regression budgets and artifact hash; a copied log with an
injected failure was rejected as its negative control. This audit prepares
reviewable changes and records their limits; it does not certify a release or
claim that source review proves absence of all defects.

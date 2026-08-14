# OpenSpec requirement and task audit

Recorded on 2026-08-13 for dirty source point
`87f58be1df38444389cbca8e580e58c8f8138c01` on `main`, using Go 1.26.5 on
Darwin/arm64. This is an implementation-evidence audit, not a release verdict.
Native Linux and publication conditions remain open below.

## Audit result

- `openspec validate structural-online-presence --strict`: pass.
- Normative scope reviewed: 18 requirements, 53 scenarios, and 79 tasks.
- Current task state: 72 complete, 7 explicitly pending.
- Production removal audit: `TestProductionPresenceOwnershipSourceAudit` pass;
  no production `trackOnlineIP`, package-global `XUDPManager`, `xudpLifecycle`,
  obsolete presence modes, or single-lease `HandoffIP` remains.
- Current affected packages pass normal, race, and checkptr:
  `common/singmux/internal/mplsmux`, `common/singmux`, and `common/mux`.
- Corrected blackhole and commander regressions pass repeated race runs.
- Release contract, shell syntax, workflow YAML parse, vformat, and
  `git diff --check` pass.
- `testing/release/structural_presence.sh standard` passes end to end, including
  real interoperability, immutable version skew, and aggregate owner checks.

The audit does not turn a wired CI gate, a cross-build, a diagnostic Docker
run, or a Darwin benchmark into native Linux release evidence.

## Requirement disposition

| Requirement (all scenarios reviewed) | Authoritative evidence | Disposition |
| --- | --- | --- |
| Stable external contracts | immutable `v26.8.15` direct/Mux/XUDP/RVS/WireGuard process matrices; 40 SMUX + 40 H2MUX Xray/sing-box/Mihomo cells; frame goldens; StatsService tests | Implemented; final release still gated |
| Trusted physical peer identity | `common/net/physical_peer_test.go`, `transport/internet/udp/physical_peer_test.go`, transport virtual-connection tests, inbound worker/provider spoof/fallback tests | Implemented |
| Immutable authenticated scope | `common/session` scope tests and dispatcher principal framing, account separation, movement, and entropy-fallback tests | Implemented |
| One-shot presence ownership | reservation terminal races, allocation-free no-op tests, idempotent lease close, exact batch handoff tests | Implemented |
| Explicit ownership mode | dispatcher Context/External/Untracked tests plus SMUX, legacy Mux, reverse, and cached-backend mode assertions | Implemented |
| Exact built-in OnlineMap leases | exact token/generation/exhaustion, legacy coexistence, unregister/re-register, stale-release tests in `app/stats` | Implemented |
| Atomic exact handoff | same/different-IP replacement, malformed/duplicate token rejection, instance/generation fallback, owner-excluded batch tests | Implemented |
| Direct request ownership | accepted-route activation, route failure, context terminal, TCP/UDP StatsService, and direct version-skew tests | Implemented |
| SMUX and H2MUX stream ownership | service stream/control/close tests, StatsService stream tests, real 80-cell interop | Implemented |
| Transactional legacy Mux sessions | duplicate ID, late preparation, token-qualified terminal convergence, TCP/packet-UDP StatsService and version-skew tests | Implemented |
| Attachment-owned XUDP runtime | runtime/principal/non-reusable isolation, destination freeze/mismatch, detach/cache/expiry tests | Implemented |
| Transactional XUDP rebind | begin-commit/shutdown barriers, stale callback, first-write failure, blocked sink/backend, 1,000-rebind zero test, version skew | Implemented |
| Reverse RVS data-slot ownership | selected-carrier scope, idle/control zero, slot StatsService, DRAIN/Closing, full Portal/Bridge/VLESS drain, 1,000-slot zero, version skew | Implemented |
| Route-time reverse carrier claim | recognized Portal carrier versus ordinary same-outbound dispatcher tests | Implemented |
| Authenticated WireGuard endpoint ownership | outer-endpoint adapter, handshake/binding zero, flow ownership, batch roam, stale generation, removal/close, 1,000-handoff zero, StatsService and version skew | Implemented |
| Shutdown and lock discipline | deterministic owner/runtime/service/Portal/Bridge/VLESS/WireGuard barriers under `-race -count=100`, reentrant callback tests, explicit joins | Implemented for reviewed paths |
| Telemetry degradation does not fail traffic | disabled policy, missing stats/provenance, alternative-map fallback, policy resampling, sanitized rate-limited warning tests | Implemented |
| Deterministic verification and release | repository-wide vet/unit/checkptr/race, critical interleavings, and 10,000 aggregate owner operations are green; executable release gate and 17-artifact cross-build exist | Partially satisfied: tasks 10.3, 10.4, and 11.1-11.5 remain open |

The 10,000-owner requirement is the deterministic sum of 7,000 exact owners,
1,000 XUDP rebinds, 1,000 RVS slots, and 1,000 WireGuard handoffs. Every batch
asserts exact zero after closure.

## Task-by-task disposition

| Tasks reviewed | Evidence/disposition |
| --- | --- |
| 1.1-1.5 | Complete; base, ancestry, dirty state, active change, old binary, frame and repository baselines are retained in `preflight.md`. |
| 2.1-2.10 | Complete; RED/GREEN history and neutral/exact/direct tests exist and current affected packages pass. Stable `OnlineMap` remains unchanged. |
| 3.1-3.11 | Complete; stream/packet provenance, virtual transport propagation/no-op behavior, authenticated snapshots, and compatibility gates are represented by direct tests and recorded command results. |
| 4.1-4.4 | Complete; structural stream ownership and control zero are direct tests; real post-optimization SMUX/H2MUX interop passed 40/40 each. |
| 5.1-5.8 | Complete; registry transaction, duplicate/late/terminal tests, runtime ownership, StatsService, stress, and immutable version skew are direct evidence. |
| 6.1-6.9 | Complete; per-owner runtime, attachment/rebind transactions, close drains, 1,000 rebinds, and old/new XUDP process traffic are direct evidence. |
| 7.1-7.7 | Complete; carrier claim, RVS slots, lifecycle joins, 1,000 slots, StatsService, and old/new RVS process traffic are direct evidence. |
| 8.1-8.7 | Complete; authenticated endpoint, flow ownership, atomic roam, drains, 1,000 handoffs, StatsService, and old/new process traffic are direct evidence. |
| 9.1 | Complete; exact StatsService tests exist for direct TCP/UDP, SMUX/H2MUX, legacy Mux TCP/packet UDP, XUDP, RVS, and WireGuard. |
| 9.2 | Complete; each of the five immutable `v26.8.15` harnesses runs old-to-new, new-to-old, and new-to-new; candidate servers assert online and final zero. |
| 9.3 | Complete; real Xray/sing-box/Mihomo server cells preserve payload assertions and add exact online/final-zero assertions. |
| 9.4 | Complete; 7,000 + 1,000 + 1,000 + 1,000 deterministic operations end at exact zero. |
| 9.5 | Complete; degraded warnings are rate-limited and tests reject email, principal, and raw-address disclosure. |
| 9.6 | Complete; production source audit is green and direct Context compatibility is tested explicitly. |
| 9.7 | Complete after correction below; release docs, test entrypoint, and pinned Ubuntu workflow make required gates fail closed. |
| 10.1 | Complete; the canonical standard gate passes end to end: vformat, `go vet ./...`, `go test -timeout 2h ./...`, full checkptr/race, real SMUX/H2MUX interop, all five immutable version-skew matrices, and aggregate owners. External DoH/DoQ/TCP DNS tests use local protocol fixtures; allocation budgets skip only measurement under detected checkptr instrumentation; VMess mux UDP and Shadowsocks 2022 UDP use full-path readiness. |
| 10.2 | Complete; 26 barrier-controlled tests across ten packages passed `-race -count=100`, with terminal zero/join assertions. |
| 10.3 | **Pending.** Native pinned Linux 50-cycle stress, 30-minute mixed-path soak, real `yt`, and zero-delta interface evidence have not run on this candidate. |
| 10.4 | **Pending.** Darwin and emulated Linux are diagnostic only; three authoritative native Linux runs and all performance/resource budgets are absent. |
| 10.5 | Complete; 17 release-flag Linux binaries and inspection records remain in `/tmp/xray-release-matrix-87f58be1`; amd64 SHA-256 is `dd9d625d2004835ff1391de7d6489f95f43ecfa3d0e1f0fd0905d2b88318dafb`. |
| 10.6 | Complete by this audit; no task listed above is inferred from a build or wired future gate. |
| 11.1-11.5 | **Pending.** No fetch/merge/release-version bump, push, tag, GitHub release, official asset verification, or OpenSpec archive has been performed. |

## Audit correction: real mixed-path soak

The first audit pass found one indirect claim: the 30-minute Linux loop only
repeated in-process aggregate owner tests, so it was not the specified
mixed-path soak. A RED release-contract assertion proved the omission.
`testing/release/structural_presence.sh linux` now runs, on every timed cycle:

1. the real SMUX and H2MUX Xray/sing-box/Mihomo interoperability matrices;
2. direct, legacy Mux, XUDP, RVS, and WireGuard immutable version-skew process
   matrices (payload integrity plus candidate-server online/final-zero checks);
3. aggregate exact-owner, XUDP, RVS, and WireGuard race batches.

The contract test and shell syntax are green after the correction. This proves
executable coverage only; task 10.3 remains pending until the complete loop
passes on the pinned native Linux runner with zero health-counter deltas.

## 1. Preflight and frozen baselines

- [x] 1.1 Record the clean implementation base, Go/host versions, dirty state, and ancestry proofs that `816ae651` is an ancestor while `0ee156e7` and `a65687a3` are not.
- [x] 1.2 Prove `structural-online-presence` is the only active online-presence change and record removal of the empty `fix-online-ip-lifecycle-tracking` stub.
- [x] 1.3 Record current source occurrences of package-global `XUDPManager`, context-owned dispatcher tracking, and carrier-derived mux/reverse ownership as explicit removal targets.
- [x] 1.4 Freeze and run the existing `common/mux` frame golden tests and record the immutable `v26.8.15` old-binary/config baseline.
- [x] 1.5 Record baseline repository test failures caused by external network/assets separately and prove every package affected by the first production slice is green before edits.

## 2. Neutral contracts, exact stats, and direct ownership

- [x] 2.1 RED: add `common/session` tests for immutable scope, allocation-free no-op objects, one-shot reservation terminals, explicit ownership modes, and concurrent idempotent lease close; observe the intended failures.
- [x] 2.2 GREEN: implement the minimal neutral presence subject/provider/tracker/reservation/lease/scope and private context mode metadata; run `common/session` tests and race.
- [x] 2.3 RED: add `app/stats` and adapter tests for pinned-instance authority, generation/token non-reuse, identity exhaustion, malformed replacement, shared-IP legacy/exact refs, batch owner exclusion, and unregister/re-register isolation; observe failures.
- [x] 2.4 GREEN: deepen the private built-in exact adapter with pinned-instance identity and fail-closed exact replacement while preserving the stable `features/stats.OnlineMap` interface; run targeted tests and race/count stress.
- [x] 2.5 RED: add dispatcher tracker tests for exact-instance pinning, strict replacement validation, owner-excluded batch handoff, alternative/different-instance degraded ordering, and sanitized rate limiting; observe failures.
- [x] 2.6 GREEN: implement the private exact/degraded adapter seam without changing routing/stats feature interfaces; run dispatcher/stats tests and race.
- [x] 2.7 After task 3.10, RED: add direct `Dispatch`/`DispatchLink` tests proving route-time activation, exact cancellation, early route-failure release, half-close behavior, and no acquisition in External/Untracked modes; observe failures.
- [x] 2.8 After task 3.10, GREEN: migrate direct ownership and delayed route acceptance to trusted structural leases while preserving traffic wrappers; remove the superseded direct `AddIP`/`RemoveIP` callback path.
- [x] 2.9 After tasks 2.7-2.8, run format, targeted vet, checkptr, race `-count=100`, and full tests for `common/session`, `app/stats`, and `app/dispatcher`; fix every new failure before continuing.
- [x] 2.10 Preserve stable legacy `AddIP`/`RemoveIP` compatibility while proving structural owners use only the private exact capability and degraded fallback.

## 3. Trusted physical peer and authenticated subjects

- [x] 3.1 RED: add canonicalization and principal golden tests for IPv4/mapped IPv4/IPv6, zone/port removal, invalid/loopback/unspecified rejection, deterministic account framing, inbound isolation, and non-reusable entropy fallback.
- [x] 3.2 GREEN: implement canonical peer conversion and keyed authenticated principal derivation behind the provider; run targeted tests and race.
- [x] 3.3 RED: add stream-listener tests proving the raw accepted TCP/Unix peer survives PROXY/TLS/REALITY/mask wrapping separately from effective `RemoteAddr`.
- [x] 3.4 GREEN: capture and expose immutable raw stream peers at the system listener and propagate them through TCP workers without changing routing/log source semantics.
- [x] 3.5 RED: add WebSocket, HTTP Upgrade, gRPC, SplitHTTP H1/H2/H3 tests proving raw connection/QUIC peers survive XFF and multi-request virtual connections.
- [x] 3.6 GREEN: propagate the raw peer through HTTP `ConnContext`, virtual connection adapters, and creator-request state for all HTTP transports.
- [x] 3.7 RED: add direct UDP, mKCP, Hysteria, finalmask/XDNS, and XHTTP/3 tests proving raw kernel/QUIC peers are frozen or the exact path stays no-op; synthetic/virtual/original-destination metadata cannot replace them.
- [x] 3.8 GREEN: propagate trusted packet peers through every evidenced packet/QUIC adapter and make every path lacking raw provenance, including synthetic finalmask/XDNS, explicitly untracked.
- [x] 3.9 RED: add authenticated VLESS/Trojan/VMess/inbound-worker tests proving the provider snapshots user plus trusted peer after authentication and before frame source rewriting.
- [x] 3.10 GREEN: wire provider snapshots into built-in authenticated inbound owners and expose the optional provider source without changing stable dispatcher interfaces.
- [x] 3.11 Run the full transport/auth package unit, race, checkptr, vet, VLESS/REALITY, spoofed-PROXY/XFF, and process compatibility gates; fix every failure before mux work.
- [x] 3.12 RED/GREEN: prove explicit `acceptProxyProtocol` trusts only a successfully parsed canonical PROXY source for authenticated presence, while disabled, missing, malformed, `LOCAL`, Unix, and non-IP cases remain raw or untracked as specified and an unchanged accepted source remains valid.
- [x] 3.13 RED/GREEN: capture accepted PROXY provenance at the parser/listener seam and preserve it independently through WebSocket, HTTP Upgrade, gRPC, and SplitHTTP so later trusted XFF or virtual-source rewriting cannot replace the presence peer.

## 4. SMUX and H2MUX structural stream owners

- [x] 4.1 RED: add service-level tests for idle carrier zero, one/two stream refs, stream close with live carrier, carrier loss, failed downstream commit, H2 request cancellation, and Brutal/control/keepalive zero.
- [x] 4.2 GREEN: pass one immutable carrier scope into the in-tree service and store one External lease beside every accepted data stream's resources; converge terminal paths on one stream close primitive.
- [x] 4.3 Prove no in-tree SMUX/H2MUX carrier or control path enters Context ownership and no stream lease waits for carrier cancellation.
- [x] 4.4 Run SMUX/H2MUX unit/race/coverage, frame/dependency-ban tests, and real Xray/sing-box/Mihomo process interop for VLESS/Trojan, TCP/UDP, both directions, and padding on/off.

## 5. Transactional legacy Mux sessions

- [x] 5.1 RED: add client allocator tests for wraparound, occupied-ID skipping, exhaustion, limits, owner-token reuse safety, activation visibility, and shutdown barriers.
- [x] 5.2 GREEN: keep narrow client local-ID allocation policy over the shared deep Session transaction module without changing 16-bit wire IDs.
- [x] 5.3 RED: test peer reservation directly through the shared Session transaction module: reserve-before-dispatch, duplicate rejection, late activation, stale token cleanup, terminal races, reentrant callbacks, and shutdown in every phase.
- [x] 5.4 GREEN: keep peer reservation policy in the deep shared Session transaction module, remove the shallow server forwarding adapter, and preserve two-phase publication, idempotent owner close, and the in-flight shutdown barrier.
- [x] 5.5 RED: add normal Mux tests proving each committed TCP/packet-UDP session owns one External lease and an idle live carrier owns none.
- [x] 5.6 GREEN: migrate normal Mux sessions to the registry/lease bundle and start pumps only after complete publication.
- [x] 5.7 Add one `mux.Runtime` per long-lived owner with worker registration, close admission, transaction barrier, and idempotent full drain; keep XUDP behavior unchanged until its slice.
- [x] 5.8 Run frame goldens before/after, normal Mux unit/race/checkptr/vet, `-count=100` lifecycle interleavings, and old/new TCP/packet-UDP version skew.

## 6. XUDP attachment runtime and rebind

- [x] 6.1 RED: add runtime identity tests proving per-owner isolation, principal/worker-token keys, destination freeze, duplicate SessionID rejection, and absence of package-global reuse.
- [x] 6.2 GREEN: move XUDP registry and one expiry scheduler into `mux.Runtime`; make backend dispatch Untracked and flow/cache own no presence.
- [x] 6.3 RED: add initial-attachment tests for buffered first payload, publish-before-pump, exactly one lease, detach-to-cached online zero, backend EOF, and cached expiry.
- [x] 6.4 GREEN: implement token/epoch-qualified attachment publication, bounded generation-tagged pumps, detach/cache, and exact cleanup.
- [x] 6.5 RED: add deterministic barriers before/after `beginCommit`, exact handoff, Session publication, Attachment publication, old retirement, queued stale callbacks, rebind first-write failure, and shutdown; observe the split-window failures.
- [x] 6.6 GREEN: deepen the standalone XUDP rebind transaction so `beginCommit` is final authorization, Session and Attachment publication then finish, and concurrent shutdown routes through normal published-state close.
- [x] 6.7 RED: add blocked backend/sink, queue-drain, active/pending/cached shutdown, concurrent close, and scheduler-goroutine leak tests.
- [x] 6.8 GREEN: complete runtime close ordering and remove package-global `XUDPManager`, package-init scheduler, cache-owned context tracking, and obsolete cleanup paths.
- [x] 6.9 Run XUDP/mux unit, frame golden, race/checkptr/vet, `-count=100` rebind/shutdown stress, 1,000-rebind lifecycle soak, and old/new XUDP version skew.

## 7. Reverse RVS data-session ownership

- [x] 7.1 RED: add dispatcher/Portal tests proving route-time carrier claim suppresses direct online ownership while an ordinary request through the same outbound retains it.
- [x] 7.2 GREEN: implement the private route-time external-owner seam and pass immutable scopes into built-in Portal/VLESS carrier workers without changing stable outbound/dispatcher interfaces.
- [x] 7.3 RED: add RVS tests for idle/control/heartbeat zero, one/many data refs, picker-selected carrier IP, spoofed frame source rejection, policy per slot, and last-data-close with live carrier.
- [x] 7.4 GREEN: add explicit `DispatchRVS` data-slot transactions and keep ordinary/control dispatch Untracked while preserving carrier traffic/timeout accounting.
- [x] 7.5 RED: add deterministic owner close tests for handler calls, construction, periodic callbacks, late registration, activation, DRAIN fallback while Open, immediate Closing rejection, reentrant callbacks, and full core close.
- [x] 7.6 GREEN: implement full Portal/Bridge/dynamic VLESS Closed semantics: stop admission and join handler calls, construction, periodic callbacks, controls, workers, sessions, leases, timers, and mux goroutines; retain generic mux Session data cleanup.
- [x] 7.7 Run reverse/VLESS/mux unit, frame goldens, race/checkptr/vet, `-count=100` shutdown stress, 1,000-slot soak, StatsService integration, and old/new RVS version skew.

## 8. WireGuard authenticated endpoint and flow owners

- [x] 8.1 RED: add bind/device adapter tests proving authenticated public-key peer to server-observed endpoint association after inner data verification, with no inner-IP fallback and no handshake/keepalive activation.
- [x] 8.2 GREEN: implement the smallest WireGuard endpoint observation adapter and immutable generation-qualified peer binding without packet/config/public-interface changes.
- [x] 8.3 RED: add flow-owner tests for TCP/UDP activation/close, missing endpoint no-op, peer removal, server shutdown, stale binding updates, and concurrent flow admission.
- [x] 8.4 GREEN: store one External lease beside each committed gVisor flow and drain all flow owners through peer/server lifecycle.
- [x] 8.5 RED: add same/different-IP roaming tests proving authenticated data triggers one batch handoff across the frozen active set and stale close/update cannot mutate replacements.
- [x] 8.6 GREEN: implement generation-checked `HandoffAll` rebind and replacement-lease join before publishing the new endpoint binding.
- [x] 8.7 Run WireGuard unit/race/checkptr/vet, `-count=100` roam/shutdown stress, 1,000-handoff soak, standard WireGuard interop, and old/new Xray compatibility.

## 9. Cross-path integration, observability, and removal audit

- [x] 9.1 Add real StatsService scenarios for direct TCP/UDP, SMUX/H2MUX, normal Mux TCP/packet UDP, XUDP attach/cache/rebind/expiry, RVS carrier/data, and WireGuard flow/roam with exact IP lists after each barrier.
- [x] 9.2 Add a version-skew harness that builds immutable `v26.8.15` and candidate binaries and runs old-to-new, new-to-old, and new-to-new traffic plus new-server online assertions for every supported path.
- [x] 9.3 Extend real Xray/sing-box/Mihomo interop to cover structural online state without replacing payload-integrity checks or process cleanup.
- [x] 9.4 Add deterministic aggregate lifecycle soak with at least 10,000 owners, 1,000 XUDP rebinds, 1,000 RVS slots, and 1,000 WireGuard handoffs ending at zero.
- [x] 9.5 Add sanitized rate-limited degraded warnings and prove logs never contain emails, principal keys, or raw client addresses.
- [x] 9.6 Remove every final-path context/carrier/cache acquisition and obsolete global/runtime symbol; verify direct Context compatibility is the only deliberate context mode.
- [x] 9.7 Update testing/baseline/release documentation and CI so all mandatory race, checkptr, vet, interop, stress, performance, Linux, and environment gates are executable and non-skippable.

## 10. Candidate verification and correction loop

- [x] 10.1 Run vformat/gofmt checks, `go vet ./...`, `go test -timeout 2h ./...`, full checkptr, and full race; add a RED regression for every discovered production bug before fixing it.
- [x] 10.2 Run critical barrier-controlled lifecycle tests under `-race -count=100` and verify zero residual slots, leases, callbacks, resources, buffers, pumps, schedulers, timers, and goroutines.
- [ ] 10.3 On pinned Linux run the real integration matrix, 50-cycle SMUX stress, 30-minute mixed-path soak, Remnawave `yt` release interface test, and zero-delta network/interface health checks.
- [ ] 10.4 Compare `v26.8.15` and candidate in nine alternating warmed rounds; verify affected median throughput and latency regress by no more than 10%, RSS by 64 MiB, threads by 16, and FDs by 8.
- [x] 10.5 Build and inspect the complete release platform matrix with release flags; smoke `xray version`, configuration load, checksums, `file`, and `go version -m` for the Linux/amd64 artifact.
- [x] 10.6 Review every OpenSpec requirement/task against authoritative tests, source searches, command logs, interop results, and artifacts; leave no unchecked or indirect completion claim.

## 11. Stable v26.8.19 continuation release

- [ ] 11.1 Fetch latest origin/upstream main and tags, retain immutable `v26.8.15` as the pre-change compatibility peer and `v26.8.18` as the continuation rollback boundary, record that `v26.8.16` through `v26.8.18` are published and unavailable, merge latest `origin/main` and `upstream/main` plus the reviewed migration into canonical `main`, and rerun all release gates on the exact merged commit.
- [ ] 11.2 Bump `core/core.go` to `26.8.19`, verify `core.Version()`, commit the release-only change, and rerun version/build smoke tests. If upstream occupies `v26.8.19`, first merge that upstream release into the combined history, then choose a new unused higher version and update this OpenSpec before tagging.
- [ ] 11.3 Push canonical `main`, create and push annotated tag `v26.8.19`, and verify remote `main`, tag, and release workflow `head_sha` resolve to the same commit. Never move a published tag.
- [ ] 11.4 Publish the canonical GitHub Release `Xray-core v26.8.19` only from the verified canonical tag, with English notes, and wait until every official workflow matrix job is green and all expected ZIP/digest assets are present.
- [ ] 11.5 Archive this OpenSpec with the immutable release tag/result, confirm `v26.8.15` compatibility and whole-binary `v26.8.18` continuation rollback with unchanged config, and mark the migration complete only after the release audit passes.

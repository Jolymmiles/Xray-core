## Context

The built-in stats manager exposes `user>>><email>>>online` as a refcounted set of unique IP strings. The previous dispatcher called `AddIP` and attached `RemoveIP` to the request context. That approximation was acceptable only for a direct logical request. SMUX, H2MUX, legacy Mux, XUDP, and reverse RVS have independent logical lifetimes inside longer-lived carriers, so context/carrier ownership leaves stale entries, cannot transfer a rebind, or counts an idle transport as online.

The original pre-change implementation base is `v26.8.15` (`816ae651`), which remains the immutable compatibility peer. Canonical continuation work now starts from `v26.8.18` (`90a94762`) because `v26.8.16` through `v26.8.18` were published before completion. The experiments `0ee156e7` and `a65687a3` are not ancestors and are prior art only. The change must integrate with the current in-tree `common/singmux` stack, Brutal controls, H2MUX, pooled inbound contexts, reverse workers, and WireGuard device. StatsService/CLI results, protobuf/config schemas, and wire formats are compatibility boundaries.

The principal stakeholder is the Xray server operator relying on exact Remnawave/StatsService online state under multiplexing, rebind, roaming, and shutdown. Linux/amd64 is the release and performance target; Darwin is a development platform only.

## Goals / Non-Goals

**Goals:**

- Make online state true exactly when at least one committed logical data owner exists for an authenticated user and canonical server-observed physical IP.
- Store one idempotent presence lease beside each owner's data resources and close or transfer it through the same token/generation-checked lifecycle.
- Keep idle carriers, controls, heartbeats, keepalives, cached XUDP backends, and unauthenticated synthetic paths offline.
- Preserve traffic accounting, public StatsService/CLI behavior, protocol bytes, configuration, and old/new interoperability.
- Make duplicate admission, late callbacks, rebind/roam, and shutdown deterministic and race-safe.
- Release the complete migration as `v26.8.19` only after all unit, race, checkptr, vet, interop, stress, performance, and Linux gates pass; `v26.8.16` through `v26.8.18` were published before completion and are not reusable.

**Non-Goals:**

- No new mux field, capability bit, protocol negotiation, protobuf, JSON setting, StatsService method, database migration, TTL poller, or UI timestamp.
- No accurate-presence retrofit for an old server binary.
- No trusted use of PROXY without explicit `acceptProxyProtocol`, XFF, frame `Inbound.Source`, an inner tunnel address, Unix/domain addresses, loopback, or unspecified IP as physical presence identity.
- No context bridge, structural/legacy feature flag, package-global replacement registry, alternate online source of truth, YAMUX, or third-party mux dependency.
- No change to administrative `UnregisterOnlineMap` semantics beyond isolating detached generations from later releases.

## Decisions

### 1. Capture immutable authenticated provenance

The trusted presence IP is normally captured at the earliest raw socket `Accept` or packet `ReadFrom` boundary before XFF, protocol, mux-frame, or routing rewrites. Transports preserve this value separately from their effective `RemoteAddr`; `app/proxyman/inbound` freezes it in session metadata. When the existing `acceptProxyProtocol` option is enabled, a successfully parsed PROXY header is the operator's explicit trust decision, and the rewritten canonical remote IP replaces the raw socket peer for session presence. A missing, malformed, `LOCAL`, unchanged, or non-IP PROXY result remains untracked. The provider snapshots the selected value only after authentication has populated the user.

The value is copied into `netip.Addr`, unmapped, stripped of port/zone, and rejected when invalid, unspecified, or loopback. Private and CGNAT unicast addresses remain valid because they may be the actual peer. Missing provenance yields a no-op scope; it never falls back to effective routing metadata.

This keeps the trust decision at the transport seam. A PROXY-enabled listener must be reachable only from trusted proxies because any accepted upstream can otherwise assert a client address. Reading `Inbound.Source` later remains rejected because XFF, reverse frames, and virtual inbounds can rewrite it without the listener-level PROXY trust contract.

### 2. Use one neutral structural interface

`common/session/presence.go` defines the only owner-facing interface:

```go
type PresenceSubject struct {
 Email        string
 Level        uint32
 IP           netip.Addr
 PrincipalKey [32]byte
 Reusable     bool
}

type PresenceProvider interface { SnapshotPresence(context.Context) PresenceScope }
type PresenceTracker interface { Prepare(PresenceSubject) PresenceReservation }
type PresenceReservation interface {
 Activate() PresenceLease
 Handoff(PresenceLease) PresenceLease
 HandoffAll([]PresenceLease) []PresenceLease
 Abort()
}
type PresenceLease interface { Close() }
```

`PresenceScope` keeps subject and tracker private, is immutable by value, and has a valid allocation-free no-op zero value. A reservation owns no online reference. Exactly one of activate, handoff, batch handoff, or abort wins. Returned leases and close operations are always non-nil, bounded, idempotent, and concurrency-safe.

`app/dispatcher/presence.go` is the sole production adapter. It derives a process-local keyed principal digest from authenticated account identity plus inbound scope, evaluates `UserOnline` policy per reservation, pins the exact stats map, and degrades telemetry failures to no-op. Email and IP are not inputs to the principal digest, so physical movement preserves identity while equal email strings cannot merge different accounts.

Three private modes are explicit: `Context` for a direct logical request, `External` for a structural owner, and `Untracked` for carrier/control/cache/synthetic work. Built-in constructors never infer a mode. `External` with a missing scope stays no-op and never falls back to context ownership. Stable `features/routing.Dispatcher`, `features/stats.Manager`, and `features/stats.OnlineMap` interfaces do not change.

Context-only mux ownership and a global observer registry were rejected because both recreate indirect lifetime coupling. A second public feature was rejected because one deep adapter hides all policy, identity, degradation, and map details behind the neutral interface.

### 3. Give the built-in OnlineMap exact capabilities

The concrete `app/stats.OnlineMap` keeps legacy and exact references separately. Each instance has a non-zero process-unique generation; each exact acquire returns a non-zero token recorded as token-to-IP under the map lock. Exact release accepts only the token, never a caller-supplied IP, so an old close cannot remove a new reference. Stable `AddIP`/`RemoveIP` continue to mutate only legacy references.

A private built-in capability supports acquire, release, instance identity, generation query, and `ReplaceOnlineLeases`. Replacement validates all distinct old tokens before mutation, consumes them, creates fresh tokens even for the same IP, and changes the complete single/batch set under one map lock. A failed validation performs no mutation. Other references on the old IP survive.

Tracker leases pin the exact map instance, generation, and token. The pinned instance is authoritative and generation is supplementary. Neither generation nor token may be reused while stale work can exist; identity exhaustion and malformed replacement fail closed without mutation. Batch handoff requires owner exclusion. Unregister/re-register leaves old leases pinned to the detached old object.

Different-instance, different-generation, or alternative maps use availability-preserving activate-new-before-close-old degraded handoff and one sanitized rate-limited warning. This rare fallback may overlap but never creates an offline gap or fails traffic. Extending the stable stats interface and string-only exact handoff were rejected because exact ownership is private and stale owners cannot be distinguished by IP strings.

### 4. Put each lease beside its data owner

| Path | Structural owner | Commit and terminal boundary |
| --- | --- | --- |
| Direct TCP/logical UDP | Accepted request context plus routed link | Activate at route acceptance; close on full request/link terminal cancellation or pre-handoff route failure. |
| SMUX/H2MUX | Accepted non-control stream | Activate before stream publication; close on stream terminal close/error, carrier loss, or service shutdown. |
| Legacy Mux | Token-qualified server session | Reserve before dispatch; activate and publish resources together; close on End/full error/cancel/worker shutdown. |
| XUDP | Current generation-qualified attachment | Activate initial attachment; atomically hand off at rebind commit; detach closes immediately while backend may stay cached. |
| Reverse RVS | Accepted data slot on selected carrier worker | Activate before slot publication; close on data-session terminal path. Carrier/control/heartbeat never activate. |
| WireGuard | Active logical TCP/UDP flow for authenticated peer | Activate at gVisor flow commit; authenticated endpoint roam batch-handoffs every active flow; handshake/keepalive alone does nothing. |

One-direction TCP half-close is not terminal until the owning protocol state machine performs a full logical close. All terminal routes converge on one idempotent owner primitive. No stats callback or blocking I/O runs while a lifecycle lock is held.

### 5. Separate admission from publication

Legacy mux uses one deep private Session transaction module over token-qualified slots plus a narrow client allocation module. Client IDs are allocated locally without overwriting occupied 16-bit IDs. Peer-supplied server IDs are reserved directly by the deep transaction module before any dispatcher/presence work, so duplicates are rejected without touching the existing owner.

Slots progress through allocated/reserved, preparing, activating, active, closing, and closed states. Resources and reservation are candidates until `BeginCommit` joins an in-flight barrier. Presence activates outside the lock. `FinishCommit` publishes link, cancel, lease, and owner token atomically; only then may pumps start. Close and stale callbacks compare `(SessionID, ownerToken)`.

Owner shutdown changes Open to Closing, rejects admission, marks pending work close-requested, detaches active bundles, cancels and closes outside locks, waits for authorized/late commits to clean up, and signals Closed only at zero slots/leases/callbacks. After commit authorization there is no rollback: publication finishes and queued close runs through the normal terminal path.

The existing one manager and overwrite behavior were rejected because peer-supplied IDs need reservation semantics different from local allocation and stale cleanup needs more identity than the wire ID.

### 6. Make XUDP state per owner and attachment-scoped

Each long-lived mux owner has one private runtime containing its flow registry, worker/transaction barrier, clock, and one expiry scheduler. Reusable keys are `(PrincipalKey, GlobalID)` only when the subject is securely reusable; otherwise `(workerOwnerToken, GlobalID)` restricts reuse to one authenticated carrier. Target network/address/port is frozen and mismatches are rejected. There is no package-global registry.

An XUDP flow owns backend I/O and bounded pumps, not presence. Its current attachment owns the server slot, carrier response sink, epoch/token, and lease. One deep rebind transaction owns validation, exact handoff, Session-slot publication, Attachment publication, old retirement, and post-authorization close routing. Preparation buffers the first payload and starts no goroutine. `beginCommit` is final authorization: before it failure preserves the old attachment; after it Session slot and Attachment publication must finish, and concurrent shutdown closes the published state through the normal terminal path. Postcommit write failure closes the new attachment and never resurrects the old one.

Every queued write/read/expiry/close callback captures flow token, epoch, and attachment token; mismatches may clean only callback-owned data. Detach immediately removes presence and enters cached state. Expiry may evict only the same detached generation. Runtime close drains transactions, attachments, flows, pumps, buffers, and scheduler before completion.

A parent-derived `context.WithoutCancel` backend owner and cached-backend presence were rejected because backend reuse is not evidence of an online logical client. The runtime instead creates an explicit flow-owned cancellation context, copies only dispatch values through a narrow context wrapper, keeps prepublication cancellation bridged to the transaction, and transfers cancellation ownership to the published flow.

### 7. Claim reverse carriers at route time

Generic `app/reverse.Portal` learns that a request is a carrier only after routing. Direct online activation therefore moves to route acceptance while traffic wrappers remain pre-route. A private optional outbound capability accepts a recognized carrier's link plus immutable scope as externally owned. If Portal declines an ordinary request, direct context ownership activates normally; a recognized carrier setup failure never falls back.

VLESS `RequestCommandRvs` can classify the carrier after authentication and passes its scope directly. Client workers retain the immutable carrier scope but use it only for `DispatchRVS` data-slot transactions. Ordinary dispatch creates control slots without presence. Generic mux Session cleanup remains the terminal data-slot owner; no RVS-specific cleanup module is added. While the reverse owner is Open, DRAIN carriers are lowest-priority fallback only when no non-draining replacement exists. Closing immediately rejects new data slots. Portal/dynamic inbound and bridge/dynamic outbound owners signal Closed only after admission, handler calls, construction, periodic callbacks, controls, workers, sessions, leases, timers, and mux goroutines drain.

Carrier wrapping remains for traffic/timeout accounting. Removing it entirely was rejected because online ownership and byte accounting are separate concerns.

### 8. Bind WireGuard presence to authenticated outer endpoints

A WireGuard-specific adapter observes the kernel UDP endpoint through the bind/device seam and associates it only after WireGuard authentication and allowed-IP verification identify the configured public-key peer. The first authenticated inner data packet publishes the binding; handshake and empty keepalive packets do not. The binding stores provenance and active flow wrappers but owns no lease itself.

When authenticated data arrives from a new canonical IP, a generation transaction snapshots active wrappers, prepares the new subject, calls `HandoffAll`, then joins replacement leases before publishing the new binding. Stale observers cannot move it backward. Peer removal blocks new flows then drains active owners. Generic TUN without authenticated outer provenance stays untracked.

Publishing the inner tunnel address was rejected because it is configured virtual identity, not a server-observed physical peer. Polling WireGuard UAPI state was rejected because it lacks an exact data-lifecycle commit point.

### 9. Degrade telemetry, never transport correctness

Anonymous/no-email users, disabled policy, and unsupported paths quietly use no-op objects. Missing trusted provenance, stats lookup/registration failure, different-instance/generation degraded handoff, alternative-map fallback, and impossible stale transitions emit rate-limited warnings without email, principal key, or raw address. Production adds no new public metrics or config. Transport/lifecycle errors still abort or close their exact owner and are never hidden as telemetry failure.

### 10. Prove compatibility and release as one unit

Every production slice is test-first and runs its affected race package before the next slice. Mux frame goldens remain byte-identical after every mux edit. Integration tests build the immutable old side from `v26.8.15`, exercise old-to-new/new-to-old/new-to-new for direct, Mux, XUDP, RVS, and WireGuard, and reuse the real Xray/sing-box/Mihomo SMUX/H2MUX matrix. New-server cells assert exact StatsService state.

The release candidate must pass format, full tests, vet, checkptr, full race, deterministic `-count=100` interleavings, 10,000-owner lifecycle soak, Linux 50-cycle SMUX stress, 30-minute mixed-path soak, interface-health checks, and nine-round baseline performance within 10%. No skipped mandatory environment is green.

## Risks / Trade-offs

- **[A logical owner closes through several concurrent terminal paths]** -> One token-qualified close primitive detaches under lock and closes resources/lease outside it; duplicate close is a no-op and race tests force every interleaving.
- **[Two-phase stats and lifecycle locks expose short transition states]** -> Guarantees apply after the transition returns; exact single/batch map replacement is one linearization point, and owner publication never precedes lease activation.
- **[An alternative OnlineMap lacks private exact replacement]** -> Activate replacements before closing old leases, warn once, preserve traffic and availability, and keep strict atomicity inside the built-in adapter.
- **[Raw peer propagation is missed by a virtual transport]** -> The transport matrix has explicit tests for every built-in inbound; absence becomes visible no-op telemetry and cannot silently trust rewritten metadata.
- **[XUDP rebind or WireGuard roam fails after handoff]** -> Commit is irreversible; close the new owner and never resurrect old presence. Precommit tests prove old state remains untouched.
- **[Lifecycle bookkeeping adds hot-path overhead]** -> Keep the owner interface small, avoid new dependencies/goroutine-per-packet work, use one scheduler per runtime, and enforce same-runner 10% throughput/latency budgets.
- **[Mixed releases observe different online semantics]** -> Wire/config remains compatible and exactness is required only on a new server. `v26.8.15` remains the immutable pre-change compatibility peer; rollback of the continuation replaces the whole candidate binary/container with current immutable `v26.8.18`.
- **[Administrative map replacement hides a prepared old generation]** -> Leases pin exact instances for safe release, but unregister remains an explicit visibility reset; no hidden pinning semantics are added.

## Migration Plan

1. Delete the empty superseded OpenSpec stub and commit this proposal/design/spec/tasks as the sole active online-presence plan.
2. Add neutral contracts, exact map tokens/handoff, and the production tracker through RED-GREEN-REFACTOR.
3. Propagate trusted raw peers and build authenticated principal scopes across all inbound transports, then migrate direct ownership without any interim effective-source fallback.
4. Migrate SMUX/H2MUX streams, then transactional legacy Mux sessions.
5. Replace global XUDP state with per-owner runtime and attachment transactions.
6. Migrate reverse RVS data slots and owner drains.
7. Add authenticated WireGuard endpoint binding and batch flow handoff.
8. Add cross-path StatsService, version-skew, third-party interop, soak/performance, CI, and legacy-path deletion.
9. Continue from canonical `main` at `v26.8.18`, merge latest `origin/main`, latest `upstream/main`, and the reviewed migration, rerun all release gates, bump and verify version `26.8.19`, push `main`, create/push the annotated `v26.8.19` tag, publish the canonical GitHub release, and wait for the official Linux asset matrix. If upstream first occupies the candidate version, merge that upstream release before selecting a new unused higher version.

There is no data/config migration and no feature flag. Compatibility canaries use the exact candidate artifact with immutable pre-change `v26.8.15`; continuation rollback uses the whole current `v26.8.18` artifact. Any pre-publication failure blocks `v26.8.19`. Published tags/assets are never moved or replaced.

## Open Questions

None. Implementation discoveries that alter ownership, trust, compatibility, or acceptance update this active OpenSpec before production code continues.

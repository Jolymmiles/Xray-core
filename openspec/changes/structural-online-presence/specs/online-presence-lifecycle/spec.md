## ADDED Requirements

### Requirement: Stable external contracts

The system SHALL implement structural online presence without changing mux/XUDP/RVS/WireGuard wire bytes, protobuf or user configuration schemas, StatsService/CLI metric names, traffic accounting, or unique-IP result semantics.

#### Scenario: Old and new peers exchange unchanged traffic

- **WHEN** a `v26.8.15` and candidate binary communicate in either client/server direction using a supported direct, Mux, XUDP, RVS, or WireGuard path
- **THEN** the transport and payload complete without negotiation or configuration changes
- **AND** only a candidate server is expected to provide the new exact online semantics

#### Scenario: Public stats remain compatible

- **WHEN** a caller queries `user>>><email>>>online` through the existing StatsService or CLI
- **THEN** the response uses the existing key, count, and IP-list representation
- **AND** traffic counters retain their previous behavior

### Requirement: Trusted physical peer identity

The system MUST derive presence IP only from a value-owned server-observed stream or packet peer captured before PROXY, XFF, protocol, mux-frame, routing, or virtual-source rewriting. It MUST canonicalize the peer as an unmapped `netip.Addr`, remove port and zone, and reject invalid, unspecified, loopback, Unix, domain, or unknown addresses without using an effective-source fallback.

#### Scenario: Rewritten metadata cannot spoof presence

- **WHEN** a valid raw TCP or UDP peer is followed by a different PROXY source, XFF value, or mux `Inbound.Source`
- **THEN** the authenticated presence scope contains only the canonical raw peer IP

#### Scenario: Missing provenance is untracked

- **WHEN** an authenticated request has an email but no valid server-observed physical peer
- **THEN** traffic continues with a no-op presence scope
- **AND** no rewritten or virtual source is published as online

#### Scenario: Synthetic packet source is untracked

- **WHEN** a packet, finalmask, or XDNS adapter exposes only a synthetic address and cannot prove its raw kernel or QUIC peer
- **THEN** traffic continues with a no-op presence scope
- **AND** the synthetic address never becomes Presence IP

#### Scenario: Canonical address forms share identity

- **WHEN** peers `192.0.2.1` and `::ffff:192.0.2.1` are captured
- **THEN** both map to the same IPv4 presence key `192.0.2.1`
- **AND** a valid IPv6 peer is published in the existing canonical bracketed format

### Requirement: Immutable authenticated scope

The system SHALL snapshot an immutable `PresenceSubject` only after protocol authentication and before per-frame source rewriting. The subject SHALL contain email, policy level, canonical physical IP, an opaque process-local principal key, and whether cross-carrier reuse is secure. Email and IP MUST NOT be inputs to the principal digest; authenticated account identity and inbound scope MUST be inputs.

#### Scenario: Physical movement preserves principal

- **WHEN** the same authenticated account and inbound scope reconnect from another physical IP
- **THEN** both scopes have the same opaque principal key but different presence IPs

#### Scenario: Equal emails do not merge accounts

- **WHEN** different authenticated account material uses the same email
- **THEN** the derived principal keys differ

#### Scenario: Principal derivation cannot be trusted

- **WHEN** deterministic authenticated account framing or secure entropy fallback fails
- **THEN** the scope is marked non-reusable or no-op
- **AND** it cannot key cross-carrier XUDP state

### Requirement: One-shot presence ownership

The system SHALL expose one neutral scope/reservation/lease interface with allocation-free non-nil no-op objects. A reservation SHALL publish no reference before commit; exactly one of activation, single handoff, batch handoff, or abort SHALL win; every returned lease SHALL close idempotently and concurrency-safely.

#### Scenario: Abort publishes nothing

- **WHEN** an owner prepares then aborts a reservation before commit
- **THEN** the online map is unchanged
- **AND** later terminal calls on that reservation publish nothing

#### Scenario: Activation and close are exactly once

- **WHEN** many goroutines race activation/abort and later race repeated lease close
- **THEN** at most one reference is acquired
- **AND** that reference is released exactly once

#### Scenario: Batch handoff preserves cardinality

- **WHEN** a reservation batch-handoffs N distinct active leases
- **THEN** it returns N corresponding replacement leases or N no-op leases
- **AND** every supplied old lease is consumed exactly once

### Requirement: Explicit ownership mode

Every built-in dispatch path MUST explicitly select `Context`, `External`, or `Untracked`. `Context` SHALL be used only when one accepted request context is the logical owner; `External` SHALL suppress dispatcher online acquisition because a structural owner holds the lease; `Untracked` SHALL never acquire. Missing scope in `External` MUST remain no-op and MUST NOT fall back to context ownership.

#### Scenario: External owner does not double count

- **WHEN** a mux stream owns an external lease and invokes the default dispatcher
- **THEN** the dispatcher preserves traffic accounting but acquires no second online reference

#### Scenario: Untracked work remains offline

- **WHEN** a carrier, control, heartbeat, keepalive, cached backend, or synthetic internal dispatch performs traffic work
- **THEN** neither the dispatcher nor another wrapper acquires online presence

### Requirement: Exact built-in OnlineMap leases

The stable `features/stats.OnlineMap` contract SHALL remain compatible. The private built-in exact adapter SHALL pin the concrete map instance, assign a non-zero generation per map instance, and assign a fresh non-zero token per structural reference. Exact release MUST use only the pinned instance and token. Stable string-based `AddIP`/`RemoveIP` mutation may coexist only as legacy references and MUST NOT act as exact ownership identity.

#### Scenario: Stale release cannot remove replacement

- **WHEN** an exact lease is handed off and its old token is released afterward
- **THEN** the replacement entry and token remain unchanged

#### Scenario: Legacy and structural references coexist

- **WHEN** one legacy reference and multiple structural leases share an IP
- **THEN** releasing one kind leaves the other references visible
- **AND** the entry disappears only after every legacy and structural reference is released

#### Scenario: Map generation is isolated

- **WHEN** a map is unregistered, a new map with the same metric name is registered, and an old lease closes
- **THEN** the old lease mutates only its captured detached map
- **AND** the new map generation remains unchanged

### Requirement: Atomic exact handoff

The private built-in exact adapter MUST require every old lease to pin the same concrete map instance as the reservation; generation is supplementary and never substitutes for instance identity. The built-in map MUST validate and replace one or more distinct exact tokens under one lock. A successful replacement MUST consume every old token, create pairwise-distinct fresh tokens even for the same IP, preserve unrelated refs, and expose only the complete before or after state. Generation and token identities MUST NOT be reused while stale work can exist. Identity exhaustion, malformed replacement, and validation failure MUST perform zero mutation. Batch handoff MUST execute with owner exclusion.

#### Scenario: Different-IP replacement is atomic

- **WHEN** all active leases for one owner move from IP A to IP B
- **THEN** concurrent map iteration observes either the complete A set or complete B set
- **AND** never observes an intermediate empty or combined owner set

#### Scenario: Same-IP replacement refreshes ownership

- **WHEN** an active lease hands off to the same canonical IP
- **THEN** visible unique/ref counts are unchanged
- **AND** the old token is replaced with a fresh token and last-seen is refreshed

#### Scenario: Alternative map fallback preserves availability

- **WHEN** the stable map adapter lacks the private exact capability or the old and new leases pin different instances or generations
- **THEN** new references activate before old references close
- **AND** traffic continues with one sanitized rate-limited degraded warning

### Requirement: Direct request ownership

A direct authenticated TCP or logical UDP request SHALL own one `Context` lease from accepted route commit until its full logical terminal event. Pre-handoff routing failure MUST release immediately; an asynchronous dispatcher return or one-direction half-close alone MUST NOT release an otherwise owned request.

#### Scenario: Direct request closes exactly

- **WHEN** a direct request becomes active and later reaches full handler/context terminal close
- **THEN** its canonical IP is visible while active and absent immediately after the close completes

#### Scenario: Route failure does not leave presence

- **WHEN** direct link creation succeeds but route selection finds no accepting handler
- **THEN** the prepared or active context lease is closed without waiting for an unrelated caller cancellation

### Requirement: SMUX and H2MUX stream ownership

An authenticated SMUX or H2MUX carrier SHALL retain one immutable scope but own no lease. Every accepted non-control data stream SHALL prepare and store one `External` lease before stream publication and close it with that stream's terminal resources. Brutal/control streams, prefaces, idle carriers, and keepalives MUST remain untracked.

#### Scenario: Closed stream does not stick to live carrier

- **WHEN** a data stream opens and closes while its carrier remains connected
- **THEN** its online reference is removed immediately after stream close
- **AND** the idle live carrier reports zero

#### Scenario: Concurrent streams refcount independently

- **WHEN** two data streams for the same user/IP are active and one closes
- **THEN** the IP remains visible until the second closes
- **AND** the public unique-IP count remains one

#### Scenario: Control traffic is offline

- **WHEN** an authenticated carrier performs only H2/Brutal control or keepalive traffic
- **THEN** it creates no reservation or online entry

### Requirement: Transactional legacy Mux sessions

The system SHALL separate locally allocated client slots from peer-supplied server reservations. Every slot SHALL have a monotonic owner token; server duplicate IDs MUST be rejected before dispatch; link, cancel, lease, and token SHALL publish together only after commit authorization; pumps MUST start only after publication. All cleanup MUST compare both session ID and owner token.

#### Scenario: Duplicate peer ID cannot overwrite

- **WHEN** a peer sends `StatusNew` for an occupied session ID
- **THEN** the new candidate performs no dispatch or presence activation
- **AND** the existing active slot and lease remain unchanged

#### Scenario: Late result cannot resurrect slot

- **WHEN** shutdown or cancellation removes a pending reservation before its dispatcher or tracker returns
- **THEN** the late candidate closes its own resources and lease
- **AND** it cannot publish or delete a later reuse of the same wire ID

#### Scenario: Session terminal paths converge

- **WHEN** peer End, EOF, write error, context cancellation, carrier loss, and shutdown race
- **THEN** one owner close detaches the slot and closes each resource and lease exactly once

### Requirement: Attachment-owned XUDP runtime

XUDP reusable state MUST live in one runtime per long-lived mux owner. A reusable flow SHALL be keyed by runtime, authenticated principal, and GlobalID and SHALL freeze the complete destination. A flow/backend/cache SHALL own no lease; only the current token/epoch-qualified attachment SHALL own the server slot, carrier sink, and one lease. Non-reusable scopes MUST be isolated to one worker token.

#### Scenario: Detach is offline while backend stays cached

- **WHEN** an active XUDP attachment detaches but its healthy backend remains reusable in cache
- **THEN** presence becomes zero immediately
- **AND** later reuse can attach without treating cache lifetime as online

#### Scenario: Principal and runtime isolation

- **WHEN** equal GlobalIDs appear for different principals, non-reusable workers, or runtime instances
- **THEN** their backends and attachments never merge

#### Scenario: Destination mismatch is rejected

- **WHEN** an existing reusable key is requested with a different network, address, or port
- **THEN** the candidate is rejected before commit
- **AND** current backend, attachment, and presence remain unchanged

### Requirement: Transactional XUDP rebind

An XUDP rebind SHALL prepare independently while the old attachment remains current. One deep rebind transaction MUST validate flow token, old epoch/attachment token, server reservation, target, and runtime state before `beginCommit`. A successful `beginCommit` is final authorization: Session-slot and Attachment publication MUST finish, and concurrent shutdown MUST close the published state through the normal terminal path. Failure before `beginCommit` MUST preserve old state and MUST NOT send first payload; failure afterward MUST close new state and MUST NOT resurrect old state.

#### Scenario: Successful rebind moves presence

- **WHEN** a valid rebind from physical IP A to IP B commits
- **THEN** the built-in online map atomically consumes the old token and publishes only B for that attachment
- **AND** stale old close/write/expiry callbacks cannot affect the new epoch

#### Scenario: Precommit failure preserves old attachment

- **WHEN** prepare, dispatch, cancellation, target validation, or shutdown fails before `beginCommit` authorization
- **THEN** the old attachment, lease, epoch, backend, and traffic path remain current
- **AND** the candidate first payload is never written

#### Scenario: Postcommit write failure does not roll back

- **WHEN** first backend enqueue/write fails after `beginCommit` authorization
- **THEN** the new attachment and lease close and the failed flow is evicted as appropriate
- **AND** the retired old attachment never becomes current again

#### Scenario: Runtime shutdown drains generations

- **WHEN** runtime close races active attachment, pending rebind, blocked backend input, blocked old sink, expiry, and duplicate close
- **THEN** admission stops, callbacks/pumps unblock, buffers are released, all leases close, and no runtime goroutine remains

### Requirement: Reverse RVS data-slot ownership

An RVS carrier and its control/heartbeat traffic MUST remain untracked for online presence while retaining existing traffic accounting. Each accepted data slot SHALL prepare and publish one lease using the selected authenticated carrier worker's immutable physical scope. Peer frame source and the incoming public request source MUST NOT replace that scope.

#### Scenario: Idle reverse carrier is offline

- **WHEN** a live RVS carrier exchanges control and heartbeat traffic without a data slot
- **THEN** its authenticated user reports online zero

#### Scenario: Data slots follow selected carrier

- **WHEN** the picker accepts data slots on workers with different canonical carrier IPs
- **THEN** each slot publishes its selected worker's IP
- **AND** spoofed frame/local source metadata changes neither entry

#### Scenario: Last data close does not require carrier close

- **WHEN** the last RVS data slot closes while its carrier remains alive
- **THEN** online state returns immediately to zero
- **AND** control traffic may continue without reacquiring presence

#### Scenario: DRAIN is availability fallback only while Open

- **WHEN** no non-draining RVS carrier is available while the reverse owner is Open
- **THEN** a non-full DRAIN carrier may accept a data slot as the lowest-priority fallback
- **AND** entering Closing immediately rejects every new data slot

#### Scenario: Reverse owner close is a full drain

- **WHEN** Portal, Bridge, or dynamic VLESS reverse owner closes concurrently with handler calls, worker construction, registration, activation, periodic callbacks, picker work, and controls
- **THEN** admission, handler calls, construction, callbacks, monitors, timers, tasks, workers, registries, runtimes, data leases, and mux goroutines are drained before Closed is signaled

### Requirement: Route-time reverse carrier claim

The default dispatcher SHALL delay direct online activation until an outbound accepts route ownership while preserving pre-route traffic wrappers. A built-in Portal recognizing its configured carrier domain SHALL claim the immutable scope as `External`; a normal request through the same outbound SHALL decline the claim and retain direct `Context` ownership. Recognized carrier setup failure MUST NOT fall back.

#### Scenario: Portal distinguishes carrier from normal request

- **WHEN** one request is recognized as a Portal carrier and another ordinary request selects the same outbound
- **THEN** the carrier contributes no direct lease and passes its scope to the worker
- **AND** the ordinary request retains its own direct lease

### Requirement: Authenticated WireGuard endpoint ownership

WireGuard presence MUST bind a configured authenticated public-key peer to the canonical server-observed outer endpoint after authenticated inner data passes peer/allowed-IP verification. The binding itself, handshake, and empty keepalive MUST own no lease. Each active logical TCP/UDP flow SHALL own one lease; a new authenticated data endpoint SHALL generation-handoff all active flow leases before publishing the new binding.

#### Scenario: Tunnel address is never published

- **WHEN** a configured peer sends authenticated data from an outer endpoint and an inner allowed IP
- **THEN** presence uses only the outer canonical IP
- **AND** the inner tunnel IP is never used as fallback

#### Scenario: Handshake and keepalive remain offline

- **WHEN** a peer exchanges only WireGuard handshake or empty keepalive packets
- **THEN** endpoint state may update internally but no online lease activates or moves

#### Scenario: Roaming moves all active flows atomically

- **WHEN** authenticated inner data for a peer arrives from a new outer IP while N logical flows are active
- **THEN** one batch transaction replaces all N leases with the new IP before publishing the binding generation
- **AND** a stale observer or close from the old generation cannot revert or remove the new state

#### Scenario: Peer removal drains flows

- **WHEN** an authenticated peer is removed or the WireGuard server closes
- **THEN** new flow admission stops and all active flow resources and leases close before completion

### Requirement: Shutdown and lock discipline

Every structural owner SHALL implement `Open -> Closing -> Closed`, reject admission after Closing, and join pending/authorized commit work before signaling Closed. Lifecycle locks MUST protect only state and ownership; dispatcher calls, presence operations, callbacks, network I/O, cancellation, close, and waits MUST execute outside those locks.

#### Scenario: Shutdown during every commit phase is exact

- **WHEN** deterministic barriers place shutdown before dispatch return, during activation/handoff, or immediately before publication
- **THEN** the candidate either rolls back completely before authorization or publishes then closes through the normal owner path
- **AND** no slot, resource, lease, callback, or goroutine remains after Closed

#### Scenario: Reentrant inspection cannot deadlock

- **WHEN** a tracker or cleanup callback re-enters owner inspection while activation or close is in progress
- **THEN** the operation completes because no callback executes under the lifecycle lock

### Requirement: Telemetry degradation does not fail traffic

Disabled online policy, anonymous/no-email users, unavailable stats, missing trusted provenance, unsupported virtual paths, alternative lease maps, and cross-generation handoff SHALL produce real or no-op ownership as specified without turning telemetry failure into transport failure. Operationally unexpected degradation SHALL be rate-limited and MUST NOT log email, principal keys, or raw client addresses.

#### Scenario: Stats lookup fails

- **WHEN** an otherwise valid logical owner cannot obtain or register its online map
- **THEN** its traffic path continues with a no-op lease
- **AND** one sanitized rate-limited warning records degraded telemetry

#### Scenario: Policy changes affect new reservations only

- **WHEN** `UserOnline` policy changes while a lease is active
- **THEN** the active lease keeps its committed ownership
- **AND** the next reservation or rebind samples the new policy

### Requirement: Deterministic verification and release

The migration MUST be released only as one complete structural implementation after all specified paths and removals are covered by deterministic tests, repository-wide format/test/vet/checkptr/race gates, real mixed-version and Xray/sing-box/Mihomo interoperability, lifecycle stress, Linux interface/resource/performance gates, and official release asset verification.

#### Scenario: Critical interleavings pass repeatedly

- **WHEN** reserve/activate/handoff/close/reuse/shutdown cases run with barriers under `-race -count=100`
- **THEN** there are zero races, deadlocks, stale mutations, double releases, residual leases, or leaked resources

#### Scenario: Lifecycle soak returns to zero

- **WHEN** at least 10,000 aggregate owners open/close including at least 1,000 XUDP rebinds, 1,000 RVS slots, and 1,000 WireGuard handoffs
- **THEN** every batch ends with exact zero residual leases and owned resources

#### Scenario: Linux candidate stays within release budgets

- **WHEN** the exact candidate runs the 50-cycle SMUX stress, 30-minute mixed-path soak, interface-health checks, and nine alternating `v26.8.15`/candidate performance rounds on pinned Linux
- **THEN** there are zero crashes/panics/races/traffic mismatches/interface error deltas/stale leases
- **AND** final RSS growth is at most 64 MiB, threads at most 16, FDs at most 8, and median affected throughput/latency regression at most 10%

#### Scenario: Stable release and rollback boundary

- **WHEN** all gates pass on canonical merged `main`, version reports `26.8.19`, official workflow assets and digests are green, and the GitHub release is published from annotated tag `v26.8.19` at the same commit
- **THEN** the migration is complete and the OpenSpec may be archived with tag `v26.8.19`
- **AND** compatibility remains proven against immutable pre-change `v26.8.15`, while continuation rollback consists only of deploying the immutable `v26.8.18` binary/container with unchanged configuration
- **AND** canonical release history includes latest `origin/main` and `upstream/main`; if upstream occupies `v26.8.19`, that upstream release is merged first and only then is a new unused higher version selected
- **AND** no published tag is moved

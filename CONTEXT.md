# Xray Online Presence

Language for deciding when an authenticated Xray user appears in online statistics.

## Language

**Trusted carrier peer**:
The immutable network peer observed by Xray at the raw socket or packet boundary for the connection or creator request, before PROXY, XFF, or mux metadata rewriting.
_Avoid_: Client IP, real IP, remote address

**Effective source**:
The request source used for routing and access logs after configured proxy, header, or frame overrides; it is not trusted for online presence.
_Avoid_: Trusted peer, presence IP

**Presence IP**:
The canonical IP derived from the trusted carrier peer and stored in an authenticated presence subject; it excludes port and IPv6 zone and never comes from the effective source.
_Avoid_: Source IP, frame IP

**Authenticated carrier binding**:
The association between an authenticated user or device principal and its current trusted carrier peer. A roaming transport may replace the peer IP without changing the principal.
_Avoid_: Tunnel IP, reported IP

**Presence subject**:
The immutable authenticated identity used for online accounting: metric email, policy level, presence IP, and an opaque process-local principal identity.
_Avoid_: User context, connection metadata

**Presence scope**:
A snapshot that couples one presence subject to the capability that can reserve its online ownership. A missing trustworthy subject produces a no-op scope.
_Avoid_: Carrier context, online record

**Presence reservation**:
A pre-commit candidate for online ownership that has not yet added an online reference. It can be activated, transferred from an old lease, or aborted exactly once.
_Avoid_: Pending lease, temporary online

**Presence lease**:
One committed online reference owned by exactly one logical data session or attachment. Closing it is idempotent and releases only that reference.
_Avoid_: Connection flag, carrier presence

**Lease token**:
The unique identity of one exact committed presence reference within a map generation. A successful handoff consumes old tokens and creates replacements.
_Avoid_: IP key, refcount ID

**Presence generation**:
The identity of one published map or carrier-binding state. Operations from an older generation cannot mutate its replacement.
_Avoid_: Timestamp, revision number

**Logical data session**:
One independently closable user data exchange carried directly or inside a multiplexed transport. It is the normal owner of a presence lease.
_Avoid_: Carrier stream, socket connection

**RVS carrier**:
An authenticated reverse transport that carries control and data slots between a Portal and Bridge. Its availability alone does not make its user online.
_Avoid_: Reverse session, online tunnel

**RVS control slot**:
The heartbeat and drain-state exchange inside an RVS carrier. It is traffic-accounted but never owns presence.
_Avoid_: Control session, keepalive lease

**RVS data slot**:
One public data request accepted onto an RVS carrier. It owns exactly one lease for that carrier's authenticated subject and trusted physical IP.
_Avoid_: Carrier connection, frame source

**DRAIN**:
The RVS carrier state that lowers a carrier to last-choice admission while an owner remains open; it may accept a data slot only when no non-draining replacement is available. Closing forbids all new data slots.
_Avoid_: Closed, unavailable

**Portal Closed**:
The terminal reverse-owner state reached only after admission has stopped and handler calls, construction, periodic callbacks, workers, logical data sessions, presence leases, and mux goroutines have drained.
_Avoid_: Handler removed, picker empty

**Carrier**:
A transport that can carry multiple logical data sessions or protocol controls over one physical connection. Its existence alone never represents online presence.
_Avoid_: User session, online connection

**Attachment**:
The current association between a reusable XUDP backend and one authenticated carrier session. The attachment, not the cached backend, owns presence.
_Avoid_: Flow cache, backend session

**XUDP flow**:
A principal-scoped reusable packet backend and its pumps within one mux runtime. It may be attached or cached, but never owns online presence itself.
_Avoid_: XUDP session, online flow

**Rebind transaction**:
The exclusive attempt to replace one XUDP flow attachment with another while preserving the current attachment until presence handoff commits.
_Avoid_: Reconnect, flow replacement

**Flow epoch**:
The generation of one published attachment to an XUDP flow. Data and lifecycle callbacks from older epochs cannot mutate the current attachment.
_Avoid_: SessionID, timestamp

**Session slot**:
One admitted mux identity plus its process-local owner token and lifecycle state. It exists before publication so duplicate IDs and shutdown races cannot bypass admission.
_Avoid_: Map entry, active connection

**Session transaction**:
The reservation, preparation, activation, and atomic publication sequence that makes a logical session and its presence lease visible together or cleans both up.
_Avoid_: Dispatcher call, session constructor

**Owner token**:
The process-local identity of one use of a mux SessionID. Internal completion and cleanup must match both values so stale work cannot affect a reused wire ID.
_Avoid_: SessionID, lease token

**Cleanup bundle**:
The detached cancel handle, I/O resources, and presence lease closed outside an owner lock by the single terminal session path.
_Avoid_: Deferred cleanup, manager callback

**Vision carrier**:
The authenticated encrypted carrier whose negotiated security state is eligible for a VLESS Vision direct-copy transition. Its carrier kind and security version must be validated before that transition.
_Avoid_: Vision session, TLS connection

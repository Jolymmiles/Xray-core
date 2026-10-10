# Intentional fork behavior

Deliberate deviations of this fork from upstream `XTLS/Xray-core`. Keep them
when syncing upstream or fixing nearby code; each bullet names the tests that
guard it.

- REALITY client-version bounds are operator-configurable and carry no built-in
  default. `minClientVer` and `maxClientVer` are parsed and reach the REALITY
  handshake when the operator sets them; when either is omitted it stays nil and
  that side of the gate rejects nobody. Do not reintroduce upstream's implicit
  `26.3.27` minimum. Covered by `infra/conf/reality_clientver_test.go` and
  `transport/internet/reality/clientver_test.go`.
- The REALITY server runs from the in-tree module copy `third_party/reality`
  (a `replace` in `go.mod`). A Client Hello that offers X25519MLKEM768 in
  neither `supported_groups` nor `key_share` authenticates through its single
  X25519 key share; hellos that offer the hybrid group keep upstream's rules.
  `third_party/reality/FORK.md` lists every fork change and the update
  procedure. Covered by `transport/internet/reality/keyshare_test.go`.
- Every shipped and release-tested build uses Go 1.27.2 (`go.mod`) and
  `-tags http2legacy`, which keeps x/net's own `http2.Transport` and
  `http2.Server` (the XHTTP client, H2MUX and DoH among them; MASQUE uses only
  x/net's framer). Without the tag, Go 1.27's x/net wraps net/http. Before
  x/net v0.60.0 the wrapped client dialed once per waiting request while a
  TLS handshake hung, defeating XHTTP `xmux.maxConnections`
  (XTLS/Xray-core#6797); v0.60.0 coalesces those dials again. Dropping the tag
  still changes what a TLS terminator such as a CDN sees: the XHTTP client's
  first SETTINGS frame advertises `MAX_FRAME_SIZE` 1048576 instead of 16384.
  It also changes redial pacing when a fresh connection dies right after its
  handshake. Both modes then open about one connection per waiting request,
  the first ones back to back; with the tag HTTP/2's retry loop delays the
  rest by 1 to 32 seconds, while without it requests that miss net/http's
  pool redial with no delay and no retry limit. Covered by
  `transport/internet/splithttp/http2_dial_test.go` (one dial while a
  handshake hangs), `transport/internet/splithttp/http2_preface_test.go` (the
  client's SETTINGS with and without the tag) and
  `testing/release/build_contract_test.go` (release builds pass the tag). No
  test pins the redial pacing.
- XHTTP inbounds accept Mux.Cool TCP sessions; upstream (XTLS/Xray-core#4128)
  limits them to pure XUDP. In packet-up and stream-up the server can poke an
  idle downlink with a Mux.Cool KeepAlive (`xhttpSettings.muxKeepAliveSecs`
  and `muxKeepAliveBytes`, off by default); stream-one is never poked. Fields
  30 and 31 of the splithttp `Config` message are fork-owned: renumber them if
  upstream claims those numbers. Covered by `common/mux/server_test.go` and
  `common/singmux/xhttp_muxcool_integration_test.go`.
- XHTTP over HTTP/2 on TCP has an optional flow-control governor
  (`transport/internet/splithttp/h2flow*.go`), off unless `XRAY_XHTTP_FLOW=on`
  or `xhttpSettings.extra.h2Flow.enabled` turns it on; with it off the HTTP/2
  wiring is stock. Field 32 (`h2Flow`) of the splithttp `Config` message is
  fork-owned: renumber it if upstream claims that number.
  `transport/internet/splithttp/BASELINE.md` holds its benchmarks and gates.
  Covered by the `h2flow*_test.go` tests and
  `common/singmux/xhttp_flow_verify_integration_test.go`.
- The Hysteria client-pool cleaner (`clientManager.cleanOnce` in
  `transport/internet/hysteria/dialer.go`) snapshots the process-wide pool
  and releases the pool lock before it waits for an instance's status or a
  client's lock; upstream's XTLS/Xray-core#7107 (`c7dbfd5e`, v26.10.10) holds
  the read lock across both waits. A forced client is closed before it is
  removed, and removed only if the pool still holds that pointer, so
  overlapping passes keep a replacement client. Keep this when syncing nearby
  code. Covered by
  `transport/internet/hysteria/instance_cleanup_test.go`
  (`TestCleanerWaitingForInstanceStatusDoesNotBlockDials`,
  `TestCleanerWaitingForOneClientDoesNotBlockOthers`,
  `TestConcurrentCleanersKeepReplacementClients`).
- A Hysteria client dial honors its context as in upstream's
  XTLS/Xray-core#7119 (`61faab4d`), with two differences. `client.dial`
  checks the context after it takes the client lock: a done context and a
  free lock are both ready in the `select`, so upstream can hand a stream to
  a dial that was already canceled. A rejected authentication closes the
  QUIC connection with H3_GENERAL_PROTOCOL_ERROR (0x101) before it closes
  the response body and the HTTP/3 transport, as the official Hysteria
  client (v2.13.0) closes it; upstream closes the transport first, which
  ends the connection with code 0, after closing the unread body, which can
  send a stream cancellation first. Covered by
  `TestCanceledDialGetsNoConnection` and
  `TestRejectedAuthenticationClosesWithProtocolError` in
  `transport/internet/hysteria/dial_cancel_test.go`.
- The dispatcher routes through `Router.PickRouteTag`, the fork's
  allocation-free picker, not `PickRoute`. A routing `script` (upstream
  XTLS/Xray-core#6823) decides in both, and `NeedsSniffingAttributes` reports
  true while a script is loaded because a script can read HTTP attributes.
  Mirror any new hook upstream adds to `PickRoute` in `PickRouteTag`. Covered
  by `app/router/script_fastpath_test.go` and upstream's
  `TestRouterScriptDNSDispatcherReentry`.
  The scripts ship enabled, as upstream does, with two known risks the
  maintainer accepted on 2026-10-10 (PR #33 review findings R1-1, R1-3).
  `Pool` in `common/lua/pool.go` creates one state, about 177 KiB plus the
  script's data, per concurrent call with no bound; a plain bound would
  deadlock a routing script whose DNS lookup re-enters routing, and an
  acquisition error sends the connection to the default outbound. Scripts
  load in `Start`, after the inbound manager starts, so the first connections
  and the TUN DNS takeover probe see only the JSON rules. Do not gate the
  scripts again without the maintainer.
- The XDNS client's `WriteTo` sends without the client mutex; upstream's
  synchronous upload (XTLS/Xray-core#7095) holds it, so `Close`, which needs
  that mutex to close the resolvers, waits forever behind a resolver write
  that blocks until close. Covered by `TestClientCloseReleasesStalledWrite`
  in `transport/internet/finalmask/xdns/hardening_test.go`.
- The XDNS server reassembles upload fragments by client ID, fragment ID
  and the 3-byte nonce the client repeats in every fragment of one packet;
  upstream keys by client ID and fragment ID only. That one-byte ID repeats
  every 256 packets, so after a lost fragment a later packet completed the
  earlier entry and the server delivered a packet spliced from two. mKCP
  without a mask has no integrity check and passed the splice into the TCP
  stream (on loopback with 14 % receive-buffer drops, a 1 MiB echo through
  VLESS over mKCP over XDNS came back corrupted in 5 of 5 runs). Clients keep
  the nonce constant within a packet since fragmentation was added upstream
  (`fc8f8a45`), so the wire format is unchanged. Covered by
  `TestServerKeepsFragmentsOfDifferentPacketsApart` in
  `transport/internet/finalmask/xdns/hardening_test.go`.
- Gecko (`transport/internet/finalmask/salamander/conn.go`) quarantines a
  message ID that received chunks of two messages: a repeated index must
  carry the same bytes and chunk lengths must match the split every sender
  uses, and an entry that receives a chunk that does not fit drops every
  chunk until its original deadline, or until the global cap
  (`geckoMaxReassembly`) evicts it as the oldest entry. Upstream keys
  reassembly by remote address and a one-byte, sequential message ID only,
  so after a lost chunk a later message completed the earlier one. Do not
  restart an entry from the conflicting chunk: arrival order does not tell
  which message is newer.
  The wire format has no message identity, so a mix that stays consistent
  until it completes is still delivered and only whole-datagram integrity
  above Gecko rejects it. Gecko therefore needs an `mkcp-legacy` mask
  without a header (FNV checksum or AES-128-GCM) listed before it, except
  under a QUIC transport (hysteria, xhttp, masque); upstream accepts it
  anywhere. `CheckDatagramIntegrity` in
  `transport/internet/finalmask/datagram_integrity.go` applies the rule to
  the stream (JSON config build and `ToMemoryStreamConfig`, which also
  serves protobuf configs and the HandlerService API). The UDP dialer, the
  UDP hub and WireGuard use the masks whatever the stream network is, with
  no QUIC above them, so they call `FinalMask.CheckRawUDP`, which grants no
  QUIC exemption. Plain salamander does not fragment and stays allowed
  everywhere. Covered by `gecko_reassembly_test.go` in that package, the
  gecko cells of `TestHysteriaProcessClientMatrix`
  (`common/singmux/hysteria_integration_test.go`),
  `TestGeckoRequiresDatagramIntegrity`
  (`infra/conf/transport_finalmask_gecko_test.go`),
  `TestToMemoryStreamConfigRequiresDatagramIntegrityForGecko`
  (`transport/internet/gecko_integrity_test.go`),
  `TestRawUDPRefusesGeckoWithoutIntegrity`
  (`transport/internet/udp/gecko_integrity_test.go`) and
  `TestRawUDPInboundsRefuseGeckoUnderNominalQUIC`.
- WireGuard's TUN wrappers close once: wireguard-go closes the device itself
  when it shuts down after a failed bind, and the owner closes it again.
  Upstream's netstack TUN (`proxy/wireguard/netstack.go`) panics on the
  second close and takes down a running instance that added such an inbound;
  the kernel TUN (`proxy/wireguard/tun_linux.go`) repeats its teardown and
  closes its netlink handle concurrently. Covered by
  `TestNetTUNCloseIsIdempotent` and `TestKernelTunCloseTearsDownOnce`.
- `outbound.Manager.RemoveHandler`, which HandlerService `RemoveOutbound`
  calls, closes the handler it removes, after unpublishing it and without the
  manager lock: a port of upstream XTLS/Xray-core#7112 at `29885292ca`, open
  when ported. Removal ends what the handler's `Close` ends; in this fork that
  includes its SMUX sessions and the VLESS reverse's connected bridges, which
  upstream's reverse leaves running. The fork's reverse `Close` waits for its
  bridges, so it also cancels the reverse's context and closes each bridge's
  connection: a bridge stalled in a dial, a TLS or REALITY handshake, or the
  VLESS encryption handshake does not hold the removal. VLESS `testpre`
  pre-connects stop on `Close`, which may run more than once, and a request
  waiting for a pre-connection returns on `Close` or its own cancellation.
  That is the lifecycle part of upstream XTLS/Xray-core#7113, which upstream
  closed unmerged; its backoff and its 2 s fallback to a direct dial are not
  ported, so while the handler is open its pre-connects still redial an
  unreachable server without pause. Covered by `TestRemoveHandlerClosesHandler`
  and `TestRemoveHandlerClosesAfterUnpublishingWithoutTheLock`
  (`app/proxyman/outbound/handler_test.go`),
  `TestRemovedOutboundClosesTUNOnce` (`proxy/wireguard`), and the
  `TestRemovedReverse*`, `TestReverseCloseAborts*` and `TestTestpre*` tests in
  `proxy/vless/outbound`.
- The WebSocket client connection with early data
  (`delayDialConn` in `transport/internet/websocket/dialer.go`), which dials on
  its first write, may be read from one goroutine, written from another and
  closed from any, as a proxy does with every carrier; upstream's reads and
  writes its connection and closed flag unsynchronized. Concurrent writers or
  readers after the dial keep Gorilla's one-reader, one-writer limit. A dial that completes after
  `Close` closes the connection it dialed instead of publishing it, `Close`
  runs once, and a deadline set before the first write returns an error where
  upstream's panicked on the nil connection. The handshake and early-data
  bytes are upstream's. Covered by `TestEarlyDataConnConcurrentReadWriteClose`
  and `TestEarlyDataCloseDuringDialClosesTheDialedConnection`
  (`transport/internet/websocket/early_data_test.go`) and
  `TestReverseCloseOverWebSocketEarlyData` (`proxy/vless/outbound`).
- The maintained SMUX implementation is the in-tree stack under
  `common/singmux`. Mux-related production code must not directly import
  SagerNet, MetaCubeX, Hashicorp, or another mux implementation.
- Preserve MPL-2.0 notices and provenance for MPL-derived code. Do not copy GPL
  files into this repository. A rewrite must be behavior-driven and must not
  silently change the wire protocol.
- SMUX is the active mux scope. Do not add YAMUX or H2MUX work unless the
  maintainer explicitly requests it.

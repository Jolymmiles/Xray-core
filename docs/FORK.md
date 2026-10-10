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
  `-tags http2legacy`, which keeps x/net's own HTTP/2 client and server (XHTTP
  client, H2MUX, MASQUE, DoH). Without the tag, Go 1.27's x/net wraps
  net/http. Before x/net v0.60.0 that client dialed once per waiting request
  while a TLS handshake hung, defeating XHTTP `xmux.maxConnections`
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
  client's SETTINGS) and `testing/release/build_contract_test.go` (release
  builds pass the tag). No test pins the redial pacing.
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
- The maintained SMUX implementation is the in-tree stack under
  `common/singmux`. Mux-related production code must not directly import
  SagerNet, MetaCubeX, Hashicorp, or another mux implementation.
- Preserve MPL-2.0 notices and provenance for MPL-derived code. Do not copy GPL
  files into this repository. A rewrite must be behavior-driven and must not
  silently change the wire protocol.
- SMUX is the active mux scope. Do not add YAMUX or H2MUX work unless the
  maintainer explicitly requests it.

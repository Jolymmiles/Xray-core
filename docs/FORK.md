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
  A server with `"requireMlkem": true` in `realitySettings` rejects such a
  hello as upstream does and forwards it to the target; it is `false` by
  default. With `true`, clients that send no hybrid key share are answered
  by the target. Seen in the review of the option: sing-box v1.14.3, which
  strips the hybrid group whatever the fingerprint; Mihomo v1.19.32 with
  default options, where by its source only `chrome` with
  `reality-opts.support-x25519mlkem768: true` keeps it (not run); Xray
  `edge`, `ios`, `qq` and the older `hello*` forms. Xray `chrome`, `firefox`,
  `safari`, their current `hello*` forms, `randomized` and
  `randomizednoalpn` pass. Xray `random` depends on the fingerprint drawn at
  process start and passes on some starts only. `android` and `360` have no TLS 1.3
  and work in neither mode. Field 100 (`require_mlkem`) of the REALITY
  `Config` message is fork-owned and outside upstream's blocks (1-13 server,
  21-27 client, 31); if upstream claims it or ships the option under another
  number or type, migrate persisted protobuf configs and API clients rather
  than renumber silently.
  `third_party/reality/FORK.md` lists every fork change and the update
  procedure. Covered by `transport/internet/reality/keyshare_test.go`.
- An inbound whose REALITY private key, ML-DSA-65 seed or a short ID is
  malformed is refused when its handler is built (`NewAlwaysOnInboundHandler`
  calls `reality.Config.CheckServerKeys`). Upstream's `GetREALITYConfig`
  panics on each, and only JSON configs check them first, so a protobuf config
  or a HandlerService `AddInbound` took the whole process down. Covered by
  `TestAddInboundRejectsMalformedREALITYKeys` in
  `app/proxyman/inbound/reality_keys_test.go`.
- Every uTLS client Xray dials with is created in the fork-owned
  `transport/internet/tls/uclient.go`: `NewUClient`, `UClient` and
  `ClientHandshake` build the ClientHello when the client is created and
  return the error, where upstream builds it during the handshake.
  `ClientHandshake`, which the TCP, WebSocket, HTTPUpgrade, XHTTP, gRPC,
  MASQUE and xdrive dialers and the XDNS DoH resolver use, closes the
  connection on any failure.
  `WithHTTP11ALPN` replaces upstream's `WebsocketHandshakeContext` without
  reading uTLS's private config; for a fingerprint without ALPN it adds the
  extension before `pre_shared_key`, where upstream appends it after, which
  breaks a handshake that resumes a session. The `randomized` and
  `randomizednoalpn` presets always offer X25519MLKEM768 with its key share
  and send key shares for X25519MLKEM768 and X25519 only; upstream draws the
  hybrid group and its key share independently, so a process could start
  with a hello that REALITY rejects, that a post-quantum-preferring server
  answers with a HelloRetryRequest uTLS cannot follow, or that breaks RFC
  8446, Section 4.2.8; the P-256 key share upstream may add is dropped, as
  Chrome sends none. The raw `hellorandomized*` forms keep uTLS's behavior. The
  REALITY client builds its hello the same way, returns an error instead of
  panicking for a fingerprint whose hello cannot carry the session ID (the
  `*_psk` forms), reads the server's certificates through `VerifyConnection`
  instead of reflection, and closes the connection on failure except when it
  hands it to the spider. The gRPC dialer completes the uTLS handshake under
  gRPC's connect context instead of on gRPC's first write. Building the
  hello at creation takes a resumption ticket from the cache then, and with
  ECH the hello is built once more. Covered by
  `transport/internet/tls/hello_snapshot_test.go` and
  `transport/internet/reality/hello_snapshot_test.go` (every byte of the
  first ClientHello of every fingerprint on each path, under fixed
  randomness), `transport/internet/tls/uclient_test.go`,
  `transport/internet/tls/randomized_fingerprint_test.go`,
  `transport/internet/tls/fingerprint_health_test.go`,
  `transport/internet/reality/uclient_test.go`,
  `transport/internet/reality/randomized_test.go` and
  `transport/internet/grpc/dial_test.go`.
- uTLS comes from the fork `github.com/Jolymmiles/utls`, branch
  `fix/keep-secondary-key-shares-a13c59f` (a `replace` in `go.mod`; the
  module path stays `github.com/refraction-networking/utls`): upstream
  `a13c59ffe98b`, the commit upstream Xray pins since v26.11.9, plus the
  changes listed in the fork's `FORK.md`. It keeps the private keys of the
  classical key shares after the first and uses the one the server selected,
  so `firefox` and the `hellofirefox_*` forms, which send key shares for
  X25519 and P-256, complete a handshake with a server that selects P-256;
  upstream fails it with "tls: invalid server key share"
  (refraction-networking/utls#402), right after the ServerHello and in
  cleartext, where Firefox goes on. The ClientHello is unchanged. It is a
  backport of refraction-networking/utls#416; drop the fork once upstream
  ships the fix. Covered by `transport/internet/tls/fingerprint_health_test.go`,
  the ClientHello snapshot tests and the fork's
  `TestSecondaryKeyShareSelectedByServer`.
- Vision takes the TLS input buffers through `proxy.VisionBuffers`
  (`proxy/vision_buffers.go`), which checks the field types and caches their
  offsets per connection type and fails closed on any other layout; upstream
  reads them by reflection on every request (`vless.AccessTLSBuffers`, which
  the fork does not carry). The raw input buffer may be held by value
  (crypto/tls up to Go 1.27, uTLS, VLESS encryption) or by pointer (the
  REALITY server since `83f621788ca8`, crypto/tls after Go 1.27, where the
  connection swaps pooled buffers). At the switch to direct copy Vision
  empties that buffer, as upstream did before XTLS/Xray-core#7176, which
  stopped out of caution about the pool Go added in golang/go `0d1836382f`.
  That pool takes a buffer back only while the connection reads and then
  drops the connection's pointer; after the switch nothing reads the TLS
  connection, so the buffer is in no pool. Without the release every Vision
  connection in direct copy keeps a record-sized buffer (about 17 KiB) until
  it closes. Covered by `proxy/vision_buffers_test.go`,
  `proxy/vision_carrier_test.go` and `TestVisionReaderSwitchTakesBufferedTLSInput`
  (`proxy/vision_reader_test.go`).
- The REALITY client's spider, which browses the site over the connection
  when the server shows a real certificate (the server forwarded the hello to
  its target, or a middlebox redirected or intercepted it), works over TCP as
  over the other transports and in upstream: the TCP dialer no longer closes
  the connection `UClient` hands to the spider, which fork commit d26e94396
  did, cutting the spider off right after the handshake. The spider owns the
  connection for a lease drawn from 660-720 s; then it closes the raw
  connection, without GOAWAY or close_notify as Chrome closes an idle HTTP/2
  connection, ending requests still in flight. Upstream keeps it until the
  peer closes. Servers close an idle HTTP/2 connection sooner by default
  (nginx after 75 s, Cloudflare after 400 s, Google Cloud load balancers after
  610 s), so with them the server still closes first; a peer that keeps the
  connection open sees the client close it after 11-12 minutes. The spider's
  requests and pauses end with the lease, and it uses its one connection only:
  a redirect to another host no longer starts a second HTTP/2 session on it,
  which the site rejected. Covered by
  `transport/internet/reality/spider_test.go` and `spider_lease_test.go`.
- Every shipped and release-tested build uses Go 1.27.3 (`go.mod`) and
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
  100 and 101 of the splithttp `Config` message are fork-owned: renumber them
  if upstream claims those numbers. Until v26.10.31 they were 30 and 31; upstream
  then gave 30 to `h2Params`, and the fork moved its splithttp fields to the
  100+ block so upstream's next numbers stay free. A protobuf config or API
  client built against the old numbers must be regenerated (JSON configs are
  unaffected). Covered by `common/mux/server_test.go` and
  `common/singmux/xhttp_muxcool_integration_test.go`.
- Outbound `mux.maxReuseTimes` sets how many sessions one Mux.Cool
  connection of the main pool admits over its lifetime before new sessions
  open another connection. The main pool also carries UDP when
  `xudpConcurrency` is 0; the XUDP pool keeps upstream's fixed 1024. It
  ports the option of XTLS/Xray-core#4231 (head `a0bf239fc1`, not merged
  upstream) with these differences: 0 or no key keeps upstream's fixed
  budget, 1024 since v26.11.9 (`bb335c6b`, 128 before), where the PR raises
  the default to 60000 and so keeps connections alive longer;
  a value outside 0-60000 fails the config, from JSON and from protobuf or
  the HandlerService API alike, where the PR clamps values above 60000 and
  lets a negative one through; `ClientStrategy.MaxConnection` keeps its
  name. The PR's `CopyChunk` frame copy, its per-session log line and its
  benchmark are not ported: the fork already drains a frame whose session
  write fails and keeps the connection, while the PR's server
  `handleStatusNew` would end it. Upstream v26.11.9 also raises a
  `concurrency` of 0-128 to 128, kept here. The budget counts admissions, not age: one
  long session keeps its connection open, and an exhausted connection closes
  once its last session ends. Field 30 of `MultiplexingConfig` is fork-owned;
  if upstream claims it or ships the option under another number or type,
  migrate persisted protobuf configs and API clients rather than renumber
  silently. Covered by `TestMuxConfigBuildMaxReuseTimes`,
  `TestNewHandlerAppliesMuxMaxReuseTimes`,
  `TestNewHandlerRejectsInvalidMuxMaxReuseTimes`,
  `TestClientManagerReplacesExhaustedCarrier`,
  `TestClientSessionManagerLargestBudgetNeverWrapsIDs`,
  `TestMuxCoolMaxReuseTimesProcess` and
  `TestMuxCoolMaxReuseTimesOldServerProcess`.
- A UDP datagram above `buf.Size` (8 KiB) stays whole when an inbound reads
  it, up to the 65535 bytes the framing's length allows, and its size never
  ends a session or a mux connection. sing-box clients send such datagrams
  whole, and so does Mihomo over VLESS (XUDP) and VMess; Mihomo's Trojan
  client splits one into packets of 8192 bytes itself. Upstream's VLESS reader
  splits one into buffers of 8192 bytes, which freedom sends as datagrams of
  their own; its VMess reader in packet mode splits one likewise, after
  filling the free space of the buffer before it when it reads both at once;
  its Trojan reader ends the UDP session on a payload above 8192 bytes; its
  Mux.Cool packet reader ends the mux connection, with every session on it, on
  a packet above `buf.Size`, and its XUDP reader fails on one. Here each of
  these readers returns the datagram in one buffer, as the SMUX reader keeps
  its datagrams whole. `buf.ReadDatagram` reads its bytes into regular buffers
  as they arrive and copies them into one buffer of its size from `bytespool`
  once the last has arrived, so a peer that announces a long datagram and
  stalls holds no more memory than it sent and one regular buffer, as with
  upstream's VLESS reader; the XUDP reader keeps its metadata buffer and the
  VMess reader its input buffer meanwhile, a second regular buffer. A
  complete datagram holds a buffer of 32 KiB (8193 to 32768 bytes) or of
  128 KiB (above), while the pipe limit counts bytes: a 512 KiB pipe of
  8193-byte datagrams holds 2 MiB where upstream's held 1 MiB, less than one
  of tiny datagrams in regular buffers holds on either. VMess chooses by the
  encoded chunk, whose tag and padding count, so with AES-GCM and no padding a
  payload of 8177 to 8192 bytes takes the copy into a 32 KiB buffer as well,
  where upstream returned a regular one. With sniffing on, the dispatcher
  lends the QUIC sniffer the first buffer of a UDP flow however long
  (`cachedReader.Datagrams`), so that a datagram longer than the 32 KiB its
  payload holds ends sniffing at once, where sniffing waited out its 200 ms
  window.
  The writers send no more than older readers take: the Mux.Cool writer drops
  a packet above `buf.Size`, where upstream's frames it; the Trojan writer
  sends up to 8192 bytes, where upstream's fails with `ErrBufferFull` from
  8182 bytes to an IPv4 address, and drops a longer datagram; the Shadowsocks
  2022 writer drops a datagram too large for a packet, where upstream's ends
  the session. The VLESS, VMess and XUDP writers already dropped what they
  cannot frame, but with global padding the VMess writer took the chunk's
  padding length from the stream it shares with the size mask before it
  dropped the datagram, and the peer, which takes one per chunk it receives,
  lost the session. It now refuses a datagram that does not fit with
  `MaxPaddingLen` (64) bytes of padding before it takes a length: one above
  8110 bytes with AES-GCM, or 8094 with authenticated length, where upstream
  sent one of up to 8174 bytes (8158) when its padding fit and otherwise lost
  the session.
  Freedom drops a datagram longer than an IP packet holds (65507 bytes over
  IPv4, 65527 over IPv6), and one its socket refuses as too long (`EMSGSIZE`),
  where upstream's freedom ends the session on that error: macOS refuses a
  datagram above `net.inet.udp.maxdgram`, 9216 bytes by default, and a
  connected socket on Linux reports a router's ICMP "fragmentation needed" for
  an earlier datagram on its next write or read; freedom's reader of a
  connected socket skips that error. The other writers to a UDP socket that a
  whole datagram now reaches drop one their socket refuses as too long and go
  on with the session, where upstream's would end it: those of the
  Shadowsocks, SOCKS, WireGuard and MASQUE outbounds, the last two of which
  also drop one longer than an IP packet holds before the write, of
  dokodemo-door in both modes (`buf.DatagramWriter` and its TPROXY writer), of
  the DNS outbound's queries, and the Shadowsocks 2022 server's reply loop.
  SOCKS encodes a datagram that a regular buffer does not hold with its header
  in a buffer of its size, inbound and outbound, where upstream sends an empty
  datagram in its place: from 8183 bytes for an IPv4 address. The TUN,
  WireGuard and MASQUE inbounds, which write replies through the same stack
  (`proxy/tun`, since upstream's #7156), drop a reply longer than an IP
  packet holds and write the next, where upstream's stack fails the write of
  one above 65527 bytes. Hysteria's UDP writer drops a datagram that
  does not fit its 8192-byte buffer with the header, as upstream's does.
  Each drop on a UDP socket or a TUN is logged at debug level by the component
  that drops it, the first of each session or socket at once and then one a
  second (`net.DropLog`), and freedom logs it with the context of its session;
  a datagram that the Mux.Cool, Trojan, Shadowsocks 2022, VLESS, VMess or XUDP
  writer cannot frame never reaches a socket, and that drop is not logged.
  Reads from a UDP socket take up to 8192 bytes; the next entry covers a
  longer datagram.
  Covered by `TestReadDatagramTakesMemoryAsTheBytesArrive`,
  `TestReadDatagramLeavesTheStreamAtTheNextDatagram`,
  `TestReadDatagramReportsAStreamThatEndsInside` and
  `TestDatagramWriterDropsDatagramsTheSocketRefusesAsTooLong` (`common/buf`),
  `TestLengthPacketReaderKeepsLargeDatagramsWhole` and
  `TestLengthPacketReaderTakesMemoryAsTheDatagramArrives`
  (`proxy/vless/encoding`), `TestAuthenticationReaderKeepsLargeDatagramsWhole`,
  `TestAuthenticationReaderTakesMemoryAsTheDatagramArrives` and
  `TestAuthenticationReaderStreamKeepsLargeChunksInOrder` (`common/crypto`),
  `TestAuthenticationWriterDropsWithoutDesyncingPadding`
  (`proxy/vmess/encoding`), `TestPacketReaderKeepsLargeDatagramsWhole`,
  `TestPacketReaderTakesMemoryAsTheDatagramArrives` and
  `TestPacketWriterSendsWhatReadersTake` (`proxy/trojan`),
  `TestPacketReaderKeepsLargePacketsWhole`,
  `TestPacketReaderTakesMemoryAsThePacketArrives`,
  `TestServerWorkerKeepsLargePacketsWhole` and
  `TestWriterDropsPacketsOlderReadersRefuse` (`common/mux`),
  `TestPacketReaderKeepsLargePacketsWhole` and
  `TestPacketReaderTakesMemoryAsThePacketArrives` (`common/xudp`),
  `TestCachedReaderLendsAFirstDatagramLongerThanThePayload` and
  `TestSniffJudgesAFirstDatagramLongerThanThePayload` (`app/dispatcher`),
  `TestUDPWriterDropsDatagramsTooLargeForAPacket` and
  `TestUDPReplyLoopDropsRepliesTheSocketRefusesAsTooLong`
  (`proxy/shadowsocks_2022`),
  `TestUDPWriterDropsDatagramsTheSocketRefusesAsTooLong` (`proxy/shadowsocks`),
  `TestEncodeUDPPacketKeepsLargeDatagramsWhole` and
  `TestUDPWriterSendsLargeDatagramsWhole` (`proxy/socks`),
  `TestUDPConnClientDropsDatagramsTooLongForIP`,
  `TestUDPConnClientDropsDatagramsTooLongForIPBeforeTheWrite`,
  `TestUDPConnClientDropsDatagramsTheSocketRefusesAsTooLong` and
  `TestUDPConnDropsRepliesTooLongForIP` (`proxy/wireguard`),
  `TestUDPConnDropsRepliesTooLongForIP` (`proxy/tun`),
  `TestProcessDropsRepliesTheSocketRefusesAsTooLong` and
  `TestPacketWriterDropsRepliesTheSocketRefusesAsTooLong` (`proxy/dokodemo`),
  `TestDNSOutboundDropsQueriesTheSocketRefusesAsTooLong` (`proxy/dns`),
  `TestMaxUDPPayload` and `TestDropLogLetsTheFirstDropThenOneASecond`
  (`common/net`), `TestPacketWriterDropsDatagramsTooLongForIP`,
  `TestPacketWriterDropsDatagramsTheSocketRefusesAsTooLong`,
  `TestPacketReaderSkipsTooLongErrorsOfAConnectedSocket` and
  `TestPacketWriterLogsTheDropsOfItsSession` (`proxy/freedom`), and
  `TestLargeUDPDatagramProcessMatrix` (`common/singmux`, integration: sing-box,
  Mihomo and Xray clients over VLESS, XUDP, Trojan and VMess with and without
  global padding).
- A read from a UDP socket takes up to `buf.Size` (8192) bytes, and the UDP
  hub, which serves the UDP side of Shadowsocks, dokodemo-door and other
  inbounds, the socket of a SOCKS UDP association (`TempUDPConn`), and
  freedom, which reads the replies, drop a datagram that a read cut short
  instead of passing its start on. Linux, macOS and the BSDs mark such a read
  with `MSG_TRUNC`, and Windows fails it with `WSAEMSGSIZE`. Where the read
  only marks it, upstream passes the first 8192 bytes on as a datagram of
  their own; on Windows the error ends freedom's session, and upstream's hub
  stops serving, so that one long datagram from anyone ends the UDP side of
  the inbound until a restart. The hub on macOS and FreeBSD reads without the
  flags and still passes a cut datagram on. `net.IsMessageTooLong` knows
  `WSAEMSGSIZE`, so on Windows freedom also drops a datagram that its socket
  refuses as too long. The readers of the SOCKS, Shadowsocks, DNS, WireGuard
  and MASQUE outbounds read a reply without those flags, from a socket or the
  userspace stack, so a read takes one byte more than a buffer holds
  (`buf.DatagramReader`, and `wireguard.UDPConnClient`'s own) and a reply that
  does not fit is dropped, where upstream's readers pass its start on and the
  Shadowsocks reader fails the cut packet's authentication and ends the
  session.
  A UDP mask (`finalmask.udp`) hides the socket from the hub and from these
  readers, on every system, and what it takes off a packet hides the cut from
  a spare byte above it: behind Salamander a reply of 9000 bytes comes out as
  8184. So below the masks of the UDP hub and of the UDP dialer, which serves
  freedom and the UDP of the other outbounds, the socket itself drops a
  datagram that its read cut short (`FinalMask.ListenRawPacket` and
  `DialRawUDP`), where upstream's masks decode the start of the packet as a
  whole one. The QUIC transports, mKCP's dialer and WireGuard, which reject a
  damaged packet themselves, keep the plain socket (`ListenPacket`,
  `DialUDP`). A mask that opens its own sockets (xdns, xicmp, udphop) reads
  them as before.
  With `sockopt.dialerProxy` and no mask, freedom's connection is that link,
  which carries buffers and has a TCP address for UDP too. Upstream's freedom
  writes to it and reads it as a stream of bytes, so a datagram of 9000 bytes
  goes on as two, of 8192 and 808, and a reply of 9000 comes back as its
  first 8192. Here freedom hands the link's buffers on, a datagram each,
  without the address of the packet, as before; the noise that the
  configuration gives as a packet crosses the link as a copy, since the link
  takes the buffer and not its bytes. The SOCKS and Shadowsocks outbounds
  write their packets to such a link with `Write`, which upstream splits into
  regular buffers, so that the rest of a packet above 8192 bytes goes on as a
  datagram of its own; a connection for a UDP destination writes each packet
  as one buffer (`cnc.Connection`). Its `Read` drops a datagram longer than
  the buffer and returns the next, where upstream's copies the start of the
  datagram without a sign, so that a UDP mask or a QUIC transport over the
  link (`FakePacketConn`) no longer takes the start of a packet for a whole
  one; `common/net/cnc/BASELINE.md` has its cost.
  Covered by `TestIsMessageTooLong`, `TestIsTruncated` and, on Windows,
  `TestIsMessageTooLongOnWindows` (`common/net`),
  `TestDatagramConnectionWritesEachPacketAsOneBuffer` and
  `TestDatagramConnectionReadDropsDatagramsLongerThanTheBuffer`
  (`common/net/cnc`),
  `TestDatagramReaderDropsDatagramsLongerThanABuffer` (`common/buf`),
  `TestHubDropsDatagramsLongerThanItsBuffer`,
  `TestMaskedHubDropsDatagramsLongerThanItsBuffer`,
  `TestHubServesOnAfterAReadOfATooLongDatagram` and
  `TestHubStopsServingOnOtherReadErrors` (`transport/internet/udp`),
  `TestTempUDPConnDropsDatagramsLongerThanTheRead` and
  `TestUDPReaderDropsPacketsLongerThanARead` (`proxy/socks`),
  `TestUDPReaderDropsPacketsLongerThanARead` (`proxy/shadowsocks`),
  `TestDNSOutboundDropsRepliesLongerThanARead` (`proxy/dns`),
  `TestUDPConnClientDropsRepliesLongerThanARead` (`proxy/wireguard`),
  `TestPacketReaderDropsDatagramsLongerThanItsBuffer`,
  `TestPacketReaderDropsRepliesCutBelowAMask`,
  `TestDialerProxyLinkKeepsDatagramsWhole`,
  `TestDialerProxyLinkTakesACopyOfConfiguredNoise` and
  `TestPacketReaderSkipsTooLongErrorsOfAPacketConn` (`proxy/freedom`), and,
  in `common/singmux` (integration), `TestLargeUDPDatagramProcessMatrix`,
  whose server drops a reply of 9000 bytes in every cell and whose Xray
  Trojan client drops a datagram above the 8192 bytes its SOCKS association
  reads, and `TestDokodemoTruncatedDatagramProcess`.
- XHTTP over HTTP/2 on TCP has an optional flow-control governor
  (`transport/internet/splithttp/h2flow*.go`), off unless `XRAY_XHTTP_FLOW=on`
  or `xhttpSettings.extra.h2Flow.enabled` turns it on; with it off the HTTP/2
  wiring is stock. Field 102 (`h2Flow`) of the splithttp `Config` message is
  fork-owned (32 until v26.10.31): renumber it if upstream claims that number.
  On the server, upstream's `xhttpSettings.h2Params` is the base HTTP/2
  config; a receive window set in `h2Flow` overrides it, and with the
  governor on the governor's 6 MiB defaults fill only a window neither sets.
  A governed server rejects an `h2Params.MaxConcurrentStreams` above the 4096
  streams the governor tracks; the governor still advertises at most 16 KiB
  frames whatever `MaxReadFrameSize` says. `h2Params` is parsed before the
  listener binds, so a bad value leaves no listener behind (upstream's
  `ListenXH` leaks it). Covered by `transport/internet/splithttp/h2params_test.go`.
  A governed server lets one connection's client hold 4 MiB of its data,
  unread or as window still open; `h2Flow.maxConnectionSendWindow` sets it
  and `-1` lifts that limit, nothing else. The limit does not hold a client
  with a governor of its own, which its own governor bounds; it loses count
  of unread data when a client raises its connection window after the
  start; and a connection whose reader pauses before the client's first
  credit loses the limit for good, even under it.
  `transport/internet/splithttp/BASELINE.md` has all three under "Limits".
  `transport/internet/splithttp/BASELINE.md` holds its benchmarks and gates.
  Covered by the `h2flow*_test.go` tests and
  `common/singmux/xhttp_flow_verify_integration_test.go`.
- The Hysteria client-pool cleaner (`clientManager.cleanOnce` in
  `transport/internet/hysteria/dialer.go`) snapshots the process-wide pool
  and releases the pool lock before it waits for an instance's status or a
  client's lock, as upstream's XTLS/Xray-core#7122 (`2bea2df6`) now does too.
  Unlike upstream, a forced client is closed before it is removed, and
  removed only if the pool still holds that pointer, so overlapping passes
  keep a replacement client; upstream deletes the key whatever it now holds.
  Keep this when syncing nearby code. Covered by
  `transport/internet/hysteria/instance_cleanup_test.go`
  (`TestCleanerWaitingForInstanceStatusDoesNotBlockDials`,
  `TestCleanerWaitingForOneClientDoesNotBlockOthers`,
  `TestConcurrentCleanersKeepReplacementClients`).
- A Hysteria client dial honors its context as in upstream's
  XTLS/Xray-core#7119 (`7c2e05dc`), with two differences. `client.dial`
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
- The dispatcher gives an outbound link's reader a timeout
  (`buf.TimeoutWrapperReader`) only where sniffing or user uplink stats need
  one (`aa7aaf17`); upstream's `WrapLink` always does. Upstream code that
  asserts `buf.TimeoutReader` on `link.Reader` has to wrap the reader itself
  when the assertion fails, and read through the wrapper from then on, as the
  HTTP outbound does to wait at most 500 ms for a first payload that a
  server-first protocol never sends (XTLS/Xray-core#7193), and the VLESS
  outbound does so the request header waits up to 500 ms for the first
  payload with sniffing on or off; upstream sends the header alone when the
  reader has no timeout. The wrapper reports a timeout as
  `buf.ErrReadTimeout`, as a pipe does (upstream XTLS/Xray-core#7327; an
  empty read before v26.11.9), and Vision then follows the header with its
  padding-only block, as in upstream. A wrapper the
  outbound creates is abandoned when the request ends
  (`TimeoutWrapperReader.Abandon`, fork-only), so a read an early return left
  pending releases its buffers when it ends. The
  Shadowsocks 2022 outbound does not wrap: its zero timeout takes only data a
  pipe already holds, and a wrapper started with a zero timeout almost never
  has the first read done, as in upstream. Callers of `buf.CopyOnceTimeout`
  (Trojan, VMess, Shadowsocks, Mux.Cool) still skip their 100 ms wait on a
  plain reader. Covered by `TestHTTPOutboundServerFirst`
  (`testing/scenarios/http_test.go`) and
  `proxy/vless/outbound/first_payload_test.go`.
- The dispatcher routes through `Router.PickRouteTag`, the fork's
  allocation-free picker, not `PickRoute`. A routing `script` (upstream
  XTLS/Xray-core#6823) decides in both, and `NeedsSniffingAttributes` reports
  true while a script is loaded because a script can read HTTP attributes.
  Mirror any new hook upstream adds to `PickRoute` in `PickRouteTag`. Covered
  by `app/router/script_fastpath_test.go` and upstream's
  `TestRouterScriptDNSDispatcherReentry`.
  The scripts ship enabled, as upstream does, in upstream's sandbox of
  whitelisted functions (XTLS/Xray-core#7136, which also refuses inline
  scripts for now), with two known risks the maintainer accepted on
  2026-10-10 (PR #33 review findings R1-1, R1-3).
  `Pool` in `common/lua/pool.go` creates one state, about 177 KiB plus the
  script's data, per concurrent call with no bound; a plain bound would
  deadlock a routing script whose DNS lookup re-enters routing, and an
  acquisition error sends the connection to the default outbound. Scripts
  compile when the config loads but run only from `Start`. A JSON-built
  config registers the inbound manager after DNS and the router
  (XTLS/Xray-core#7284), so their `Start` activates the scripts before
  any inbound listener opens, and the TUN DNS takeover probe, which runs
  from the inbound's `Start`, sees them too. Anything that routes or resolves before
  `Start` sees only the JSON rules, and its DNS lookups go to the servers;
  upstream routes through the compiled script before its pool exists and panics there.
  Covered by `TestRouterRoutesByRulesBeforeScriptStarts` and
  `TestDNSQueriesServersBeforeScriptStarts`. Do not gate the scripts again
  without the maintainer.
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
- The XDNS DoH resolver over h3 closes the UDP socket and `quic.Transport`
  of a dial that fails or is canceled; upstream (XTLS/Xray-core#7140) closes
  them only once a dial succeeds. It refuses `"congestion": "brutal"`, which
  upstream's dial meets with a panic in a goroutine nothing recovers. Covered
  by `TestDOHResolverH3ClosesTheSocketOfAFailedDial` and
  `TestNewDOHResolverRejectsBrutalCongestion` in
  `transport/internet/finalmask/xdns/resolver_doh_test.go`. Its TLS config
  names the host of its URL unless `serverName` names another. Upstream left
  the name empty: over h1 and h2 a resolver without `serverName` verified its
  server only with a pinned leaf certificate or `verifyPeerCertByName`, and
  then sent no SNI; over h3, http3 put the name in the ClientHello but a
  pinned CA was checked against the empty one and refused. The ClientHello
  over h1 and h2 now carries the URL's host as SNI, as from Go's net/http,
  curl or a browser and as over h3 already: a passive observer sees the DoH
  host name where it saw a hello without SNI, active probing meets the same
  server. A URL with an IP address still sends no SNI. The TLS config is built
  once per resolver, after its QUIC settings are checked. Covered by
  `TestDOHResolverTLSNamesTheServerOfItsURL`,
  `TestDOHResolverH3PinnedCAWithoutServerName` and
  `TestDOHResolverBuildsItsTLSConfigOnce`.
- The XDNS DoH resolver follows no HTTP redirect, over h1, h2 or h3: a 3xx
  answer is a failed query. Upstream (XTLS/Xray-core#7140) keeps Go's default
  policy, which follows up to 10 redirects to any host and turns a 301, 302
  or 303 into a GET without the query, whose page was then read as the DNS
  answer. RFC 8484 allows a DoH server to redirect; refusing is this fork's
  policy, and a server that moved needs its new URL in the configuration.
  Only a party that holds the server's TLS identity, or a certificate from a
  CA the client trusts, can send the redirect. Refused, it can no longer make
  the client connect to a host or fetch a path it names: an observer sees
  only connections to the configured server, and the query fails with a
  logged error. Covered by `TestDOHResolverRefusesRedirects` in
  `transport/internet/finalmask/xdns/resolver_doh_test.go`.
- TLS dialers build their configs with `GetClientTLSConfig`, which is
  `GetTLSConfig` without the certificate refresh workers: upstream starts one
  per certificate read from files (`encipherment` or `issue`) each time it
  builds a config, and dialers build one per connection, so an outbound with
  such a certificate in `tlsSettings` gained a goroutine per dial that ran
  until the files could no longer be read. A client never selects one of
  those certificates, as `GetCertificate` is a server's callback, and the
  config, and with it the ClientHello, is otherwise the same. Listeners keep
  `GetTLSConfig` and refresh from the start. This covers the TCP, WebSocket,
  HTTPUpgrade, gRPC, mKCP, XHTTP, MASQUE, Hysteria and xdrive dialers, the
  realm client and the XDNS DoH resolver. Covered by
  `transport/internet/tls/client_config_test.go` (no workers, and the same
  first ClientHello byte for byte for every fingerprint and crypto/tls),
  `TestDialersStartNoCertificateRefreshWorkers` in
  `transport/internet/tls/refreshtest/dialers_test.go`,
  `TestServiceClientDialsStartNoCertificateRefreshWorkers` (xdrive),
  `TestNewClientStartsNoCertificateRefreshWorkers` (realm) and
  `TestDOHResolverBuildsItsTLSConfigOnce`.
- The TUN stack copies a TCP segment that was put together from IP fragments,
  or joined because its checksum is looked at, instead of keeping the buffers
  it was read into: upstream (XTLS/Xray-core#7179) kept the buffer of the last
  piece, so the connection read other bytes than were sent or waited for
  bytes it had acknowledged. Covered by
  `TestTCPSegmentPutTogetherWithSegments` in
  `proxy/tun/fragment_kept_test.go`.
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
- WireGuard's kernel TUN wrapper (`proxy/wireguard/tun_linux.go`) closes
  once: wireguard-go closes the device itself when it shuts down after a
  failed bind, and the owner closes it again. Upstream's repeats its teardown
  and closes its netlink handle concurrently. The netstack TUN
  (`proxy/wireguard/netstack.go`), which upstream rebuilt on Xray's own
  TCP/IP stack in XTLS/Xray-core#7156, closes once in upstream too. Covered by
  `TestKernelTunCloseTearsDownOnce` and `TestNetTUNCloseIsIdempotent`.
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
- HandlerService `RemoveUser` (`xray api rmu`) on a VLESS, Trojan or VMess
  inbound closes the removed user's live connections; upstream only deletes
  the user from the validator, so its plain, UDP, Mux.Cool, XUDP, SMUX and
  reverse connections kept running (XTLS/Xray-core#5844, open, proposes a
  tracker in every inbound and the dispatcher instead). `Process` tracks each
  connection it has authenticated for a user with an email
  (`proxy.UserConnections`, `proxy/user_connections.go`); `RemoveUser`
  deletes the user, cancels each tracked connection's context and closes the
  connection the worker passed to `Process`, the one the worker closes when
  `Process` returns. The closes run in their own goroutines and `RemoveUser`
  does not wait for them. `AddUser` and `RemoveUser` are serialized per
  inbound and `AddUser` stores a copy of the user, so a connection that
  authenticated before a removal and registers after it is refused, also when
  the same email is added again. A VLESS reverse of a removed user is not
  published after the removal, and `RemoveUser` keeps the reverse of a tag
  another user of the same inbound still uses (upstream closes it). Users
  without an email cannot be removed and are not tracked. Other inbounds with
  `RemoveUser` (Shadowsocks, Shadowsocks 2022, Hysteria) still keep a removed
  user's connections. Covered by `proxy/user_connections_test.go`,
  `revoke_test.go` in `proxy/vless/inbound`, `proxy/trojan` and
  `proxy/vmess/inbound`, the `TestRemovedUser*` process tests in
  `common/singmux` and `TestCommanderRemoveUserClosesItsConnections`
  (`testing/scenarios`).
- HandlerService `RemoveInbound` (`xray api rmi`) and closing the instance
  end the inbound's live connections; upstream closes only its listeners and
  leaves each accepted connection running until it ends on its own (SMUX
  carriers and gRPC streams already ended through their own `Close`). The
  TCP and Unix socket workers track the connections they serve
  (`liveConnections`, `app/proxyman/inbound/connections.go`); `Close`
  cancels each one's context and closes it, in its own goroutine and without
  waiting, before it closes the listener, whose `Close` may wait for the
  handlers it started. A connection a closed worker receives is closed
  without being served. The UDP worker closes its sessions on `Close`, opens
  none afterwards, and an ended session no longer removes a newer session of
  the same source. The XHTTP listener over HTTP/1.1 and HTTP/2 closes its
  HTTP server as well, so the connections a client reuses for its next
  sessions end with it. Not covered: REALITY authentication and the cover
  forwarding of a failed one, which the REALITY listener runs before a
  worker sees the connection, and inbounds without workers (TUN, WireGuard),
  which close through their own `Close`. Covered by
  `app/proxyman/inbound/close_connections_test.go`,
  `TestListenerCloseEndsServedConnections`
  (`transport/internet/splithttp`) and
  `TestRemovedInboundConnectionsProcess` (`common/singmux`).
- A server connection with the `http` TCP header
  (`transport/internet/headers/http`) orders its first `Write` against
  `Close`, which removing a user now calls from another goroutine: the peer
  gets the configured response header or the error header, never both;
  upstream's unsynchronized `Conn` can send both. Covered by
  `TestServerCloseRacingFirstWriteSendsOneResponse`.
- The WebSocket client connection with early data
  (`delayDialConn` in `transport/internet/websocket/dialer.go`), which dials on
  its first write, may be read from one goroutine, written from another and
  closed from any, as a proxy does with every carrier; upstream's reads and
  writes its connection and closed flag unsynchronized. Concurrent writers or
  readers after the dial keep Gorilla's one-reader, one-writer limit. A dial
  that completes after `Close` closes the connection it dialed instead of
  publishing it, `Close` runs once, and a deadline set before the first write
  returns an error where upstream's panicked on the nil connection. The
  handshake and early-data bytes are upstream's. Covered by
  `TestEarlyDataConnConcurrentReadWriteClose`,
  `TestEarlyDataCloseDuringDialClosesTheDialedConnection` and
  `TestEarlyDataDeadlines` (`transport/internet/websocket/early_data_test.go`)
  and `TestReverseCloseOverWebSocketEarlyData` (`proxy/vless/outbound`).
- `xray run` bounds its shutdown: after SIGINT or SIGTERM it waits at most
  10 s (`closeTimeout` in `main/run.go`) for `Instance.Close`, then prints
  `Timed out while closing Xray.` and exits 1; a `Close` error prints
  `Failed to close:` and exits 1. This ports XTLS/Xray-core#6164 (head
  `09e5e23c24`), open upstream, where the CLI waits for `Close` without a
  bound and ignores its error. Unlike that head, the exit waits for the
  message at most 1 s (`exitMessageTimeout`), so a stdout nobody reads does
  not hold the process. A feature whose `Close` never returns, such as
  `app/geodata` waiting for a download nothing cancels, otherwise kept the
  process relaying established connections and swallowing further SIGTERMs
  until SIGKILL. The fork also subscribes to the signals before `Start`
  (`23b5ebbb`); keep both when syncing `main/run.go`. Covered by
  `TestShutdownAfterSignalIsBounded` (`main/run_shutdown_test.go`),
  `TestShutdownSignalDuringStartup` and, on Linux,
  `TestShutdownAfterSignalIsBoundedWhileStdoutIsBlocked`
  (`main/run_shutdown_linux_test.go`),
  `TestShutdownSignalEndsProxyingWhenCloseHangs` and
  `TestShutdownSignalClosesRelayingXray`
  (`testing/scenarios/shutdown_test.go`).
- `mux.MutexWriter`, which upstream v26.11.9 (`5745dea2`) puts in front of
  a Mux.Cool worker's link writer, forwards `Interrupt` and `Close` to that
  writer without taking its lock. Upstream's embeds only `buf.Writer`, so a
  worker that ended no longer interrupted its link: the client's carrier and
  the inbound copying a server worker's responses waited for their own
  timeouts. Covered by `TestWorkerEndInterruptsWrappedWriter`
  (`common/mux/mutex_writer_test.go`).
- The maintained SMUX implementation is the in-tree stack under
  `common/singmux`. Mux-related production code must not directly import
  SagerNet, MetaCubeX, Hashicorp, or another mux implementation.
- Preserve MPL-2.0 notices and provenance for MPL-derived code. Do not copy GPL
  files into this repository. A rewrite must be behavior-driven and must not
  silently change the wire protocol.
- SMUX is the active mux scope. Do not add YAMUX or H2MUX work unless the
  maintainer explicitly requests it.

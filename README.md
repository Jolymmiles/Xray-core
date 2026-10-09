# Project X

This repository is a server-focused fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core), part of [Project X](https://github.com/XTLS) and the XTLS ecosystem.

## DeepWiki

Explore the fork's architecture, code, and features or ask questions directly in [DeepWiki](https://deepwiki.com/Jolymmiles/Xray-core).

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Jolymmiles/Xray-core)

## Fork features

This repository tracks upstream Xray-core and maintains additional server-focused features and hardening:

- **In-tree sing-mux stack:** sing-mux-compatible `smux` and `h2mux` clients and servers with TCP/UDP streams, optional padding, bounded connection pools, and no runtime dependency on an external mux library. H2MUX is selected outbound with `smux.protocol` and auto-detected inbound. See the [wire protocol specification](common/singmux/SPEC.md).
- **Per-inbound H2MUX frame size:** `smux.h2muxMaxReadFrameSize` advertises `SETTINGS_MAX_FRAME_SIZE` to H2MUX clients, whose per-stream upload buffers scale with it. Omitting it keeps the 1 MiB library default.
- **Brutal congestion control:** opt-in Brutal bandwidth negotiation for outbound SMUX/H2MUX clients and per-inbound servers through `smux.brutal-opts` (`enabled`, `up`, and `down`). Linux servers need the `brutal` congestion-control module.
- **Structured logging:** multiple independent console, JSONL file, and Unix-socket outputs with event filtering, batching, bounded queues, and configurable backpressure. Legacy logging remains supported. See the [configuration guide](common/log/CONFIGURATION.md).
- **Exact online presence:** when `statsUserOnline` is enabled, `user>>><email>>>online`, `GetStatsOnlineIpList`, and `GetAllOnlineUsers` follow authenticated logical traffic rather than long-lived carriers. This covers direct traffic, SMUX/H2MUX, legacy Mux/XUDP, reverse connections, and WireGuard flows.
- **Operator-controlled REALITY client versions:** server-side `minClientVer` and `maxClientVer` are optional and have no built-in default. An omitted bound rejects no client on that side of the range.
- **Expanded protocol sniffing:** QUIC v2 Initial packets and BitTorrent UDP traffic (uTP, DHT, and UDP trackers) can be identified for routing or blocking. QUIC sniffing reassembles a ClientHello split across Initial packets, including shuffled, retransmitted and padded ones, does not sniff a ClientHello whose repeated CRYPTO data differs (QUIC servers disagree on which copy counts, so the routed name could differ from the one the destination reads; repeats are checked only until the ClientHello is complete), follows one connection when a flow carries several, and forwards the sniffed datagrams unmodified; TLS sniffing reassembles a ClientHello fragmented across records.
- **Hysteria/Realm extensions:** Realm supports `ipMode` selection and optional UPnP/NAT-PMP port mapping; finalmask QUIC settings expose loss-compensation, Chrome-parrot, and GSO controls synchronized with Hysteria 2.13.0 behavior. The Chrome parrot is that of the apernet/quic-go version Hysteria 2.13.0 pins, which adds the trust_anchors extension; it has not been compared with a capture of Chrome. That quic-go version is also the QUIC stack of XHTTP/3, MASQUE and DNS-over-QUIC. Masquerade proxy targets accept Unix sockets as Hysteria does, and `xray tls ech` validates the public name, randomizes the config ID and takes a `--maxNameLength` hint like `hysteria ech`.
- **XDNS hardening:** the xdns finalmask rejects malformed queries before authentication without crashing, answers its zone apex authoritatively and treats only names below it as tunnel queries, keeps serving after transient read errors, and keeps decoded answers within the client's buffer. A rejected query that parses gets a well-formed DNS response, EDNS errors included, that carries only the header, the question and an OPT record of the server's, so it never echoes the query's records or outgrows the query. When even that reply would outgrow the query, which takes a question name compressed against bytes holding no earlier name (RFC 1035, Section 4.1.4), the answer is a FORMERR without the question. At most 4096 clients are tracked, each with a queue of 128 downlink packets; when the table is full, the least recently used client is evicted, where the table used to grow without bound. Client IDs come from unauthenticated polls, so about 4096 new IDs sent between two polls of a client evict it and drop up to 128 packets queued for it. xdns must be the last entry of `finalmask.udp`: server configurations that put it elsewhere, which no Xray client could use, now fail to build. Resolver addresses need a valid port; an address without a host, like `:53`, reaches the resolver on this machine, and an empty one is rejected. A configured domain is packed as its absolute ASCII name. One trailing dot is accepted. An internationalised name goes out in punycode, converted without case folding or other UTS #46 mapping, so write it in lowercase with ASCII dots. A name with an empty label, a label over 63 bytes or an `xn--` label that decodes to nothing fails to build, with an error that names it. A client and a server that use an internationalised name must be upgraded together: older fork builds and upstream Xray send it as raw UTF-8, which a newer server no longer matches.
  - Known limitations: an active prober can still tell an xdns server from an authoritative DNS server. Answers without data, the apex's included, and NXDOMAIN carry no SOA in the authority section (RFC 2308); names outside the zone get a non-authoritative NXDOMAIN where authoritative-only servers usually answer REFUSED; the OPT payload size mirrors the query's; a question with such malformed compression gets that FORMERR, where a reply built with miekg/dns, the library behind CoreDNS, carries the expanded name and is longer than the query; queries that do not parse get no reply; and replies to rejected queries are dropped while the 128-slot reply queue is full.
- **uTLS fingerprint fidelity:** session resumption falls back to a full handshake when adding ticket or PSK extensions would change the selected fingerprint's original ClientHello shape.
- **Server-path hardening:** the fork carries additional VLESS/REALITY/Vision, mux lifecycle, buffering, half-close, and UDP correctness fixes. Exact changes and validation results are documented in the [fork releases](https://github.com/Jolymmiles/Xray-core/releases).

Official fork release artifacts currently target Linux. Other platforms can be built from source. New configuration surfaces are opt-in, and existing upstream configurations remain supported, apart from the xdns placement and domain-name rules above.

## License

[Mozilla Public License Version 2.0](LICENSE)

## Documentation

[Project X Official Website](https://xtls.github.io)

## Contributing

Contributions are welcome through this repository's [issues](https://github.com/Jolymmiles/Xray-core/issues) and [pull requests](https://github.com/Jolymmiles/Xray-core/pulls). By participating, you agree to follow the [Code of Conduct](https://github.com/Jolymmiles/Xray-core/blob/main/CODE_OF_CONDUCT.md).

## Credits

- This fork is based on [XTLS/Xray-core](https://github.com/XTLS/Xray-core). Credit for the upstream implementation belongs to the Xray-core maintainers and contributors.
- Xray-core v1.0.0 was originally forked from [v2fly/v2ray-core at `9a03cc5`](https://github.com/v2fly/v2ray-core/commit/9a03cc5c98d04cc28320fcee26dbc236b3291256).
- Fork-specific changes are documented in the [release notes](https://github.com/Jolymmiles/Xray-core/releases). Third-party dependencies and their source modules are listed in this repository's [go.mod](https://github.com/Jolymmiles/Xray-core/blob/main/go.mod); source-level license and provenance notices remain authoritative.

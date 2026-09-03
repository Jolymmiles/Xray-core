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
- **Expanded protocol sniffing:** QUIC v2 Initial packets and BitTorrent UDP traffic (uTP, DHT, and UDP trackers) can be identified for routing or blocking.
- **Hysteria/Realm extensions:** Realm supports `ipMode` selection and optional UPnP/NAT-PMP port mapping; finalmask QUIC settings expose loss-compensation, Chrome-parrot, and GSO controls synchronized with Hysteria 2.12.1 behavior.
- **uTLS fingerprint fidelity:** session resumption falls back to a full handshake when adding ticket or PSK extensions would change the selected fingerprint's original ClientHello shape.
- **Server-path hardening:** the fork carries additional VLESS/REALITY/Vision, mux lifecycle, buffering, half-close, and UDP correctness fixes. Exact changes and validation results are documented in the [fork releases](https://github.com/Jolymmiles/Xray-core/releases).

Official fork release artifacts currently target Linux. Other platforms can be built from source. New configuration surfaces are opt-in, and existing upstream configurations remain supported.

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

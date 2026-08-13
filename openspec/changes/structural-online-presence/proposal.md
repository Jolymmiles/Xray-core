## Why

Xray currently ties `user>>><email>>>online` references to request or physical-carrier contexts. That lifetime is wrong for multiplexed traffic: closed SMUX/Mux streams remain online, XUDP rebind does not move presence to the new carrier, cached backends can outlive attachments, and reverse carriers count as online without a data session.

This change makes online state follow the committed logical data owner exactly while preserving protocol bytes, configuration, traffic statistics, StatsService, and mixed-version interoperability.

## What Changes

- Introduce immutable authenticated presence scopes and one-shot reservation/lease ownership for direct requests, SMUX/H2MUX streams, legacy Mux sessions, XUDP attachments, reverse RVS data slots, and WireGuard logical flows.
- Capture a canonical server-observed physical peer before PROXY, XFF, mux-frame, or virtual-source rewriting; missing trustworthy provenance is untracked rather than inferred.
- Replace string-based online-map mutation with generation-qualified leases and atomic single/batch handoff.
- Replace carrier-global session/XUDP state with token-checked per-owner registries, two-phase publication, explicit shutdown barriers, and per-runtime XUDP attachment generations.
- Make carriers, controls, heartbeats, keepalives, cached XUDP backends, and synthetic/unknown-provenance paths untracked.
- Preserve every existing mux/XUDP/RVS/WireGuard wire byte, protobuf/config schema, Stats RPC/CLI name, and unique-IP result.
- Remove the superseded context/carrier/cache ownership paths after structural owners and compatibility tests are complete.

### Supersedes

This change replaces the empty active change `fix-online-ip-lifecycle-tracking`, the context-lifecycle experiment `0ee156e7`, and the incomplete structural prototype `a65687a3`. Those are prior-art evidence only. The decisive difference is that online presence belongs to committed logical sessions or attachments, never to an outer context, physical carrier, reusable backend, worker, or cache lifetime.

## Capabilities

### New Capabilities

- `online-presence-lifecycle`: Exact authenticated online-presence identity, structural ownership, transfer, shutdown, compatibility, and release acceptance across all built-in inbound data paths.

### Modified Capabilities

None. The repository has no existing OpenSpec capability for online presence. StatsService, CLI, configuration, protocol contracts, and the stable Go `features/stats.OnlineMap` interface do not change; exact ownership remains a private built-in capability.

## Impact

Affected modules include `common/session`, `app/stats`, `app/dispatcher`, `app/proxyman/inbound`, `transport/internet`, `common/singmux`, `common/mux`, `app/reverse`, `proxy/vless`, `proxy/wireguard`, integration scenarios, and release CI. No new dependency, configuration field, wire negotiation, public core feature, protobuf, or database/state migration is introduced.

The implementation starts from `v26.8.15` (`816ae651`). The old binary remains the whole-artifact rollback boundary and the version-skew peer for the candidate `v26.8.16` release.

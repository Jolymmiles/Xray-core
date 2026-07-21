# SMUX clean-room implementation record

## Design inputs

The implementation was derived from `SPEC.md`, `ENGINE_SPEC.md`, `TESTING.md`,
`BASELINE.md`, the tests under this package, the in-tree `internal/mplsmux`
engine, and the public Xray interfaces needed to connect buffer links,
dispatchers, and outbound dialers. Compiler and test diagnostics were used to
validate those interfaces.

## Excluded inputs

The previous implementations of `client.go`, `packet.go`, `padding.go`,
`protocol.go`, `retry_conn.go`, and `service.go` were not inspected. No mux
implementation from SagerNet, MetaCubeX, xtaci, sing-box, Mihomo, a module
cache, repository history, another worktree, or an internet source was used.

## Independent architecture

The outer layer uses a least-loaded carrier set guarded by one lifecycle lock.
Each carrier hosts the in-tree MPL SMUX engine. Logical connections are adapted
directly between Xray multi-buffer links and SMUX streams. UDP uses explicit
packet reader and writer adapters that preserve a destination on every
datagram. Server admission is controlled before a stream handler starts, so
pending handshakes are bounded by the configured handler limit.

The first-response retry path is a connection decorator with independent read,
write, and state locks. It retains at most 2 MiB of bytes accepted before the
response, permits one replacement stream, and serializes replacement with
writers so replay has a stable prefix. Padding has separate read and write
state and switches each direction to the raw carrier after sixteen frames.

## Verification

The focused verification commands are:

```sh
gofmt -w common/singmux/client.go common/singmux/packet.go common/singmux/padding.go common/singmux/protocol.go common/singmux/retry_conn.go common/singmux/service.go
go test ./common/singmux/... ./common/mux
go test -race ./common/singmux/... ./common/mux
```

The broader release commands remain documented in `TESTING.md`.

# Preflight evidence

Recorded before the first production-code slice on 2026-08-12.

## Implementation base

```text
HEAD: 816ae65180cc8e8ac6bac76ffcdbc561e93ebb7d
Branch: feature/structural-online-presence
Tag at base: v26.8.15
Go: go1.26.5 darwin/arm64
Host: Darwin 25.5.0 arm64
```

Ancestry commands and results:

```text
git merge-base --is-ancestor 816ae651 HEAD   -> 0
git merge-base --is-ancestor 0ee156e7 HEAD   -> 1
git merge-base --is-ancestor a65687a3 HEAD   -> 1
```

The feature branch therefore descends from current `main`; neither historical presence implementation is an ancestor.

## Active OpenSpec changes

After deleting the empty superseded stub, `openspec list` reports:

```text
structural-online-presence            0/78 tasks
configure-default-policy-timeouts     No tasks
```

`structural-online-presence` is the only active online-presence change. The unrelated timeout change remains untouched.

## Frozen old-binary and mux baseline

The old peer was built directly from the clean source base:

```sh
go build -trimpath -o /tmp/xray-structural-preflight-v26.8.15 ./main
/tmp/xray-structural-preflight-v26.8.15 version
```

It reports `Xray 26.8.15 ... go1.26.5 darwin/arm64`. The immutable release tag `v26.8.15`, not a historical presence commit, is the old side for later version-skew tests.

The pre-change mux frame/metadata baseline is green:

```text
go test ./common/mux -run 'Frame|Metadata' -count=1
ok github.com/xtls/xray-core/common/mux
```

No protobuf, config, frame, or generated file is changed by this documentation/preflight slice.

## First-slice package baseline

```text
go test ./common/session ./app/stats ./app/dispatcher -count=1
ok github.com/xtls/xray-core/common/session
ok github.com/xtls/xray-core/app/stats
ok github.com/xtls/xray-core/app/dispatcher
```

## Repository-wide baseline failures

`go test -timeout 2h ./...` completed with exit 1 before production edits. Failures are recorded, not classified as green:

- `app/dns`: external DoH request to `1.1.1.1` returned EOF in `TestDOHNameServerWithCache`.
- `app/router`, `common/geodata`, and `infra/conf`: the isolated worktree does not contain the repository-ignored `resources/geoip.dat` and `resources/geosite.dat`; the primary checkout has those assets.
- `testing/scenarios`: existing process tests reported connection-refused/timeouts, including commander/listener scenarios, before this change.

All packages affected by the first production slice are green independently. The ignored geodata assets will be linked into the worktree test environment before the final full gate. Network/process baseline failures remain explicit evidence and must be re-evaluated; they are not permission to add or ignore any feature regression.

## Explicit removal targets

The pre-change source audit found:

- dispatcher `trackOnlineIP` plus `context.AfterFunc` ownership in `app/dispatcher/default.go`;
- carrier-derived `session.SubContextFromMuxInbound` in `common/mux/server.go`;
- package-global `XUDPManager` and package-init expiry scheduler in `common/mux/server.go` and `common/mux/session.go`;
- VLESS RVS outer-carrier `dispatcher.WrapLink` in `proxy/vless/inbound/inbound.go`.

Behavior tests will prove replacement semantics before each target is removed. A final source audit is supplementary evidence only.

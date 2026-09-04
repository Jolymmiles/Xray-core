# PR review follow-up — 2026-09-05

This follow-up addresses confirmed comments on PRs #10 and #11. Xray remains the
only proxy server in process tests; local Middle-End and cover fixtures are
supporting services. No PR is merged or release published by this follow-up.

## Changes

| Files | Purpose |
|---|---|
| `common/singmux/e2e_integration_test.go`, `stats_wait_integration_test.go` | Bound every online-IP stats RPC by one five-second context. Preserve the last IP set and RPC error for timeout diagnostics instead of issuing an unbounded final RPC. |
| `common/singmux/TESTING.md` | State the required legacy commit/full-history checkout or explicit prebuilt legacy binary. The test does not fetch implicitly or skip missing fixtures. |
| `common/singmux/smux_negotiated_halfclose_integration_test.go` | Register server and require-client failure logs before assertions, including failures before the auto client starts. |
| `main/run.go`, `main/run_signal_test.go` (both PR branches) | Register SIGINT/SIGTERM before server.Start can expose readiness, and unregister on exit. The deterministic regression delivers a signal during a feature's Start and verifies completed server.Close in a separate process. |
| `proxy/mtproxy/subprocess_integration_test.go` (PR #10) | Launch actual Xray using JSON config; exercise DD/EE traffic, HandlerService RemoveUser/RemoveInbound, exact fallback bytes, EOF, graceful shutdown and rejected clients. |
| `proxy/mtproxy/process_integration_test.go` (PR #10) | Share the existing independently acting Middle-End handshake fixture with subprocess tests and check its errors. |
| `proxy/mtproxy/SPEC.md`, `TESTING.md` (PR #10) | Distinguish executable E2E from in-process tests and retain official Telegram-client validation as a manual merge gate. |

The proposed extra echo retries, generic relay-join removal, unconditional
Middle-session removal and blanket docstring coverage edits were not supported
by the inspected contracts and were not applied.

## Reproduction and verification

Go 1.27.0, Linux/amd64. Local logs are under `/tmp/xray-audit/` and are not
committed. Expected failures are retained separately from successful runs:

- The stats regression first deadlocked in the synctest bubble because the
  actual RPC context was context.Background. After the fix, a stalled RPC exits
  at the five-second budget; matching and mismatching IP cases also pass.
- A current Xray was deliberately supplied as the legacy fixture. The test
  rejected it and captured both server and require-client logs.
- The new MTProxy process suite exposed early SIGINT termination after the
  server was already serving requests. A separate deterministic main regression
  proved lost SIGINT and SIGTERM during Start. Both pass after moving signal
  registration; the graceful shutdown assertion was retained.

Commands run on the main PR branch:

```sh
go test -tags integration ./common/singmux -run '^TestAwaitStatsOnlineIPs' -count=1
go test -race -tags integration ./common/singmux -run '^TestAwaitStatsOnlineIPs' -count=1
go vet -tags integration,stress,performance ./common/singmux
go test -tags integration ./common/singmux \
  -run '^(TestSMUXProcessInteropMatrix|TestSMUXAutoFallbackLegacyXray)$' -count=1 -v
go test ./main ./core -count=1
go test -race ./main -count=1
go vet ./main
go test -tags integration ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -v
go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
```

All passed. VLESS executed 36/36 cells and SMUX 24/24 using the new binary with
the startup-signal fix. The earlier stats/fallback run passed 24 SMUX cells and
two legacy-fallback cells. No signal-failure retry or artificial readiness sleep
was introduced. The previous audit's 300-cycle hardening is historical evidence,
not a claim that this follow-up reran that workload.

On the MTProxy branch, `XRAY_MTPROXY_E2E_BIN` selects a binary built from that
checkout; the unrelated `XRAY_E2E_BIN` is ignored:

```sh
go test ./main ./proxy/mtproxy -count=1
go vet -tags integration ./main ./proxy/mtproxy
go test -tags integration ./proxy/mtproxy \
  -run '^TestMTProxy(Subprocess|Process)' -count=3 -v
go test -race -tags integration ./proxy/mtproxy -run '^TestMTProxySubprocess$' -count=1 -v
go test -gcflags=all=-d=checkptr=2 -tags integration ./proxy/mtproxy \
  -run '^TestMTProxySubprocess$' -count=1 -v
```

The regular matrix passed 27/27 subprocess leaf cases (21 Xray processes) and
15/15 older in-process cases. Race and checkptr each passed 9/9 subprocess leaf
cases, with both Xray and the harness instrumented. A separate parent run
verified another 9/9 subprocess cases. Official Telegram Desktop/Android DD/EE
interoperability remains unexecuted; local fixtures do not establish it.

## Linux artifacts

The main binary was built with CGO_ENABLED=0, GOOS=linux, GOARCH=amd64,
GOAMD64=v1, `-trimpath -buildvcs=false -gcflags=all=-l=4` and
`-ldflags='-X github.com/xtls/xray-core/core.build=review-67addd5f -s -w -buildid='`.
Its SHA256 is `71fab89a71215f61df033770b3d25df88834065a358ef1efbe2064642287ff25`.

The regular MTProxy binary was built with the same platform/CGO settings,
`-trimpath -ldflags='-s -w -buildid='`; SHA256:
`c883a2830ea4749200ac28dcf4fa7558f97b2d2ad78337fe525d1f524b455f10`.
Its race build uses `-race -trimpath`; its checkptr build uses
`-gcflags=all=-d=checkptr=2 -trimpath` with CGO disabled. File type, SHA256 and
Go build metadata were inspected. These are pre-commit test artifacts, not
published release assets; no capacity or performance improvement is claimed.

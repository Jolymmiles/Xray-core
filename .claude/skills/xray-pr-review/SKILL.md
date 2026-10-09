---
name: xray-pr-review
description: Review a Jolymmiles/Xray-core pull request read-only, instead of `code-review`. Use for a first round, a re-review of a fix delta, or an orchestrator launching and collecting reviewers.
---

Read-only review of one PR of this fork in one context. `AGENTS.md` is already loaded: cite its sections by name, never re-read it, and spawn no sub-agents unless the round prompt assigns disjoint areas (each would re-read it and report outside the ledger).

The round prompt gives: PR number, `base`, `head`, `delta`, `ledger`, `focus`, `prior findings`, claims to verify. An orchestrator launching or collecting rounds reads [ORCHESTRATOR.md](ORCHESTRATOR.md). Any `gh` call, CI lookup or spec fetch reads [GH.md](GH.md) first (it lists the calls that fail here).

## Contract

- The PR is read-only: no edits, commits, pushes, stashes, `checkout`/`switch`/`reset` in a live checkout, no PR comments, reviews, labels or merges. `gh` calls are GET-only.
- Never call `link_pull_request`, `watch_pull_request` or `unwatch_pull_request`. Only the orchestrator watches; a reviewer that watches multiplies wake-ups.
- Writes go to `/tmp/review/` only: ledger, pinned worktree, logs, repro files. A repro test may live in your pinned worktree; copy it to `/tmp/review/pr<N>-repro/` and cite that path. The exception is git's own metadata: `git fetch` and `git worktree add` in step 1 add objects and a worktree entry to the shared git directory. They create no branch and touch no other checkout.

## 1. Pin a worktree

The implementer's checkout moves while you read. Review a detached worktree at the prompt's `head` SHA, never the live checkout.

```sh
git cat-file -e <HEAD>^{commit} || git fetch --no-write-fetch-head origin <HEAD>
git worktree add --detach /tmp/review/pr<N>-<HEAD7> <HEAD>
MAIN=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")
mkdir -p /tmp/review/pr<N>-<HEAD7>/resources
cp "$MAIN"/resources/geo{ip,site}.dat /tmp/review/pr<N>-<HEAD7>/resources/
```

`geoip.dat`/`geosite.dat` are gitignored; without them `infra/conf` tests panic. They are copied, not set up with `testing/setup-worktree.sh`, because a PR head may predate that script. Fetching by SHA also works for fork PR heads.

Each Bash call restarts in the original directory, so write `cd /tmp/review/pr<N>-<HEAD7> && export GOFLAGS=-tags=http2legacy && ...` every time; a bare command runs in the live checkout.

Done when `git -C /tmp/review/pr<N>-<HEAD7> rev-parse HEAD` equals `head` and `resources/geoip.dat` exists there. Finish with `git worktree remove /tmp/review/pr<N>-<HEAD7>` (`--force` only after saving a repro).

## 2. Review

1. **Spec.** PR body plus linked issues ([docs/agents/issue-tracker.md](../../../docs/agents/issue-tracker.md)). Done when you can state in one sentence what the PR promises and which `AGENTS.md` invariants it touches.
2. **Diff.** `git diff --stat <BASE>...<HEAD>`, then every hunk. In a re-review, read `git diff <DELTA>` and give each prior finding a disposition: fixed at `file:line`, still open, or invalid with reason. Use SHAs or `refs/heads/main`, never bare `main` (see GH.md).
3. **Judge** with the rules below. Done when each rule is applied or marked n/a with a reason.
4. **Gates** for the changed area (table below). Done when every command ran with `-timeout`, or is reported `NOT RUN` with the reason.
5. **Ledger.** Append each confirmed finding the moment it is confirmed, not at the end.

## Ledger

`/tmp/review/pr<N>.md`, append-only, shared by every round and every sub-agent. Confirmed means reproduced, or read at `file:line` on the pinned head.

```sh
cat >> /tmp/review/pr<N>.md <<'EOF'
### R<round>-<n> [High|Medium|Low|Nit] path/file.go:123 - one-line title
- Head: <HEAD SHA>
- Evidence: what the code does and why it is wrong (quote the line)
- Repro: exact command and observed output, or "reasoned only: <why not run>"
EOF
```

A suspicion you could not confirm goes under "Unverified" in the report, not in the ledger. The orchestrator reads the ledger on any terminal or failed state, so a crash after an append loses nothing.

## Severity

| Severity | Meaning | Merge |
| --- | --- | --- |
| High | Panic, unbounded memory/goroutines/fds or a hang reachable from unauthenticated or malformed input (needs a malformed-input regression test that fails before the fix; its absence is itself High). Change to established wire bytes (VLESS, Trojan, REALITY, Vision, SMUX) or to camouflage: TLS handshake or fingerprint, packet sizes or timing, lifecycle, a probe reply that differs from stock. Failed REALITY auth counted as proxy success. Fail-open on wrong UUID, key, short ID, flow or malformed framing. Corruption of unrelated mux streams. Failing sing-box or Mihomo client cell. Weakened safety, licensing, test or compatibility gate. | blocks |
| Medium | Leak or double-release on an error or shutdown path not reachable unauthenticated. Pooled buffer kept after release. Sibling implementation left unfixed. Bug fix without a test that fails without it. Test that can pass while the bug exists. Externally observable change with no stated censor-capability assessment. Performance claim without baseline update. | blocks unless the maintainer defers |
| Low | Missing error context, misleading comment or doc, off-hot-path waste. | fix if cheap |
| Nit | Style that `go run ./infra/vformat/main.go -mode check -pwd ./` or `go vet` does not already flag. | optional |

## Judgement rules

- **Sibling sweep.** For a fixed or introduced pattern (cleanup order, bound, error mapping, close path, framing check), `git grep` every sibling: other transports, inbound/outbound and client/server halves, TCP and XUDP paths, the `third_party/reality` copy, test helpers. List each as `file:line - fixed | already correct | missing | n/a (reason)`. Done when every hit has a status; `missing` is a finding.
- **Exit-path walk.** For each new queue, channel, map entry, pooled buffer, timer or goroutine, walk every exit between registration and consumer start: early return, error, panic, context cancel, peer reset, shutdown. Done when each path names who releases the resource, exactly once.
- **Stock parity.** A wrapper in front of TLS, `net` or `net/http` (listener, conn, handler, transport) must answer unauthenticated probes like the stock stack: plaintext on a TLS port, wrong ALPN, truncated or garbage preface, early close, deadline behaviour. A probe-comparison test must exist; model: `TestFlowListenerAnswersProbesLikeStock` in `transport/internet/splithttp/h2flow_verify_listener_test.go`.
- **Camouflage.** An externally observable change states which censor capabilities it considers (passive classification, active probing) with evidence and limits (`AGENTS.md` "Project direction"). A claim of absolute indistinguishability is a finding.
- **Claim check.** The prompt's and PR body's "known", "accepted", "pre-existing" and "unchanged" items are claims. Verify each against `git diff <BASE>...<HEAD>` and `git show <BASE>:<path>`. A failure called pre-existing must reproduce at the base SHA with the same command (a second pinned worktree); a claim the diff contradicts is a finding.
- **RED before GREEN.** A bug fix ships a test that fails without it; prove it by reverting the production hunk in your pinned worktree.
- **Test hygiene.** No sleeps for readiness, retries, `t.Skip`, loosened assertions or raised timeouts to go green. Every wait has an explicit deadline. Goroutines, sockets, processes and temp dirs are cleaned on every path, cleanup registered before the assertion phase. `t.Fatal`/`FailNow` only from the test goroutine. Readiness is observed through the real path (SOCKS to server to echo), not an open port. Errors are evidence: a swallowed error in a test or in connection-correctness code is a finding.

## Gates

Pointers only; the commands live in the cited places. Always `export GOFLAGS=-tags=http2legacy`; an explicit `-tags` must include `http2legacy`. Every `go test` carries `-timeout`. `-short` is for iteration; the verdict uses a full run of the changed packages.

| Changed area | Run |
| --- | --- |
| `proxy/vless`, `transport/internet/reality`, `third_party/reality`, `infra/conf` | `AGENTS.md` "Required test tiers" > "VLESS TCP and REALITY", including the 36-cell process matrix |
| `common/singmux`, `common/mux`, `app/proxyman/outbound` | "SMUX" tier; plus stress, reconnect, performance and 50-cycle commands in `common/singmux/TESTING.md` when production mux code changed |
| `transport/internet/splithttp` (XHTTP) | `go test ./transport/internet/splithttp/... -short -count=1 -timeout 300s` while iterating (about a minute), a full run for the verdict; process gates in `transport/internet/splithttp/BASELINE.md` ("Process gates") and `TestXHTTPMuxCoolProcess` in `common/singmux/TESTING.md` |
| `transport/internet/finalmask/...` | `go test ./transport/internet/finalmask/... -count=1 -timeout 300s`, then `-race`, then `go vet` on the same |
| `.github/workflows`, `testing/release`, `core` | `go test ./testing/release ./core -count=1 -timeout 300s` |
| any Go change | `go run ./infra/vformat/main.go -mode check -pwd ./`; `go vet` on changed packages; `-race` when goroutines, pools or locks change; `-gcflags=all=-d=checkptr=2` when `unsafe` or reflection changes; `git diff --check <BASE>...<HEAD> -- . ':!third_party'` |
| docs only | every cited path exists (`git ls-files`) and every cited command runs |

Process matrices need the sing-box and Mihomo clients. A head that contains `testing/interop` builds them from sources beside the checkout or beside the main checkout, so the pinned worktree needs no variables. An older head looks only beside the pinned worktree and fails there: build both clients from `$(dirname "$MAIN")/sing-box` and `$(dirname "$MAIN")/mihomo` the way `buildE2EBinaries` (`common/singmux/e2e_integration_test.go`) builds them, and export `SING_BOX_E2E_BIN` and `MIHOMO_E2E_BIN`. `XRAY_E2E_BIN` replaces the Xray build. A matrix that did not run is `NOT RUN` and a blocker, never a skip or a pass.

## Report

1. `Verdict:` blockers (High/Medium ids) or none.
2. `Findings:` ledger ids, severity-ordered, one line each.
3. `Gates:` command and result for each; `NOT RUN` entries with reason.
4. `Siblings:` the sweep table.
5. `Unverified:` suspicions not confirmed.

Done when every ledger entry of this round appears in the report, gates are listed with results, and the pinned worktree is removed.

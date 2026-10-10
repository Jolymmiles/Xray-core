# Xray-core fork development instructions

These instructions apply to the entire repository. More specific `AGENTS.md`
files may narrow them for a subtree but must not weaken the safety, licensing,
test, or compatibility gates defined here.

## Project direction

- The primary goal is to make proxy connections appear as legitimate traffic
  to a censor, resisting passive classification and active probing. Encryption
  alone does not hide proxy use. Performance and interoperability improvements
  must preserve traffic camouflage.
- When changing externally observable behavior, assess TLS handshakes and
  fingerprints, packet sizes and timing, connection lifecycle, and responses
  to unauthenticated or malformed probes. State the censor capabilities being
  considered and record relevant evidence and limitations; successful proxy
  connections and benchmarks alone do not prove camouflage. Do not claim
  absolute indistinguishability.
- Optimize and harden the Xray server first. Linux/amd64 is the release and
  performance target; Darwin is useful for development but is not evidence of
  Linux server capacity.
- Preserve protocol interoperability. In process interoperability, stress,
  reconnect, and performance tests, Xray is the only proxy-server implementation.
  Run one Xray server per topology and vary the client between Xray, sing-box,
  and Mihomo for changed VLESS, Trojan, REALITY, Vision, or mux paths. Performance
  comparisons use baseline and candidate Xray server versions. External-server
  and reversed-role topologies are outside these gates.
- Only Xray code changes. A sing-box or Mihomo interop break is fixed on the
  Xray side, never by patching those clients.
- Prefer simple, reviewable changes. Do not mix several speculative
  optimizations into one pass.
- Communicate with the maintainer in Russian unless they request another
  language. Keep code, identifiers, commit messages, and repository
  documentation in English unless an existing file establishes otherwise.

## Fork behavior, review, and releases

- Before changing REALITY, XHTTP, mux, build tags or the Go version, or when
  syncing upstream, read `docs/FORK.md`: the intentional deviations from
  upstream and the tests that guard each.
- Review of a PR or branch, and launching or collecting review rounds,
  follows `.claude/skills/xray-pr-review/SKILL.md`.
- Release work (gates, stamp, `Pre-release Validation`, tag, publish) follows
  `.claude/skills/release/SKILL.md` and starts only when the maintainer asks.

## Before changing code

1. Read `git status --short` and the relevant recent commits.
2. Read the package tests, protocol specification, baseline, and testing guide
   before modifying a protocol or performance path.
3. State the exact server path, invariant, acceptance check, and bounded work
   item. One measured hot spot or one behavior change is a normal pass.
4. Before optimizing, record the baseline as "Performance workflow" requires.

Relevant documents:

- `proxy/vless/BASELINE.md` — VLESS behavior and performance baselines.
- `common/singmux/SPEC.md` and `common/singmux/ENGINE_SPEC.md` — SMUX protocol
  and engine contracts.
- `common/singmux/TESTING.md` and `common/singmux/BASELINE.md` — SMUX and VLESS
  TCP TLS/REALITY process gates, the release gate entrypoint
  (`testing/release/structural_presence.sh`), and measurements.

## Mandatory TDD workflow

Use RED-GREEN-REFACTOR for bugs, behavior changes, unsafe/reflection work, and
performance changes:

1. Add the smallest test that fails for the intended reason.
2. Run it and save the RED evidence. A compile failure is valid only when the
   new API does not yet exist.
3. Implement the minimal production change.
4. Run the targeted test to GREEN.
5. Refactor without changing behavior and rerun the targeted package.
6. Run race, checkptr where unsafe code is involved, process E2E, and the Linux
   build gate before declaring completion.

Never weaken, skip, retry, or add sleeps to a test merely to make it green.
Readiness must be observed through the real behavior needed by the scenario.
For proxy clients, an open local SOCKS port is insufficient; prove the complete
SOCKS-to-server-to-echo path.

Every production bug found during manual, stress, fuzz, or E2E testing must
gain a permanent regression test before the fix.

## Go implementation standards

- Check formatting with `go run ./infra/vformat/main.go -mode check -pwd ./`.
  It is gofumpt-based and is the CI check; `gofmt` alone misses its rules. Fix
  only the files it reports that you changed. It skips `third_party/`, whose
  vendored modules keep their upstream bytes; only the fork-owned files listed
  in a module's `FORK.md` follow this rule.
- Use descriptive names, early returns, narrow helpers, and the simplest
  implementation that preserves the protocol.
- Add context to errors at subsystem boundaries. Never swallow an error that
  affects connection correctness, cleanup, or test evidence.
- Make connection, listener, buffer, timer, goroutine, and process ownership
  explicit. Close or release each resource on every error path and transfer
  ownership only once.
- Do not retain pooled buffers after release. Benchmark allocation changes and
  test fragmented, coalesced, empty, and error paths.
- Avoid reflection and `unsafe`. When unavoidable, validate concrete types and
  layouts, fail closed, keep unsafe arithmetic local, add invalid-layout tests,
  and pass `-race` plus `-d=checkptr=2`.
- Do not introduce goroutine-per-packet behavior, unbounded queues, blocking
  cleanup, or hidden background retries in server hot paths.
- Keep generated protobuf files generated. Change their source schema and
  regenerate instead of hand-editing generated files.

## Protocol invariants

- Preserve established VLESS, Trojan, REALITY, Vision, and SMUX wire bytes
  unless an explicitly versioned protocol change is requested.
- Fragmented and coalesced headers must preserve every payload byte.
- Plain/no-flow VLESS must not allocate Vision-only state.
- Vision remains restricted to its supported security and TLS version rules;
  do not relax authentication or direct-copy safety while optimizing.
- A failed REALITY authentication must not be counted as proxy success through
  the cover target.
- Wrong UUID, key, short ID, server name, flow, or malformed framing must fail
  closed without panic, leak, or server-wide impact.
- Mux stream and session errors must not corrupt or terminate unrelated
  streams. Backpressure must be bounded and observable.

## Performance workflow

- Profile or benchmark before editing. An optimization without a measured hot
  spot is not accepted.
- Keep an isolated microbenchmark for the changed primitive and a process-level
  benchmark or stress test for the server path.
- Record a reproducible baseline: command, source revision/dirty state, Go
  version, host OS/architecture. Run at least five samples; use medians and
  inspect variance. Compare the same commit conditions, Go version, CPU
  governor, host load, and kernel settings.
- Do not infer a nanosecond improvement from a millisecond TLS/REALITY process
  benchmark. Use the process result as a regression gate and the isolated
  benchmark as proof of the local change.
- Reject changes that do not beat noise, regress any mandatory mode by more
  than the documented budget, or trade latency for unbounded memory/resources.
- Update the relevant `BASELINE.md` with the command, conditions, before/after
  results, allocation counts, and limitations of the measurement.
- Linux runtime benchmarks must run on Linux. A cross-build proves only
  portability.

## Required test tiers

Run the narrowest applicable tier after every edit, then expand before handoff.
Export `GOFLAGS=-tags=http2legacy` first so tests, and the binaries they build,
match the release. An explicit `-tags` replaces the tags in `GOFLAGS`, so add
`http2legacy` to it.

Give every `go test` an explicit `-timeout`; a hang otherwise costs 5-10
minutes. While iterating, add `-short` where the package supports it (the
`transport/internet/splithttp` suite takes about 200 s, and its slowest tests
skip under `testing.Short()`). Handoff runs the tiers below without `-short`.

In a fresh worktree run `testing/setup-worktree.sh` once: it links the
gitignored `resources/geo{ip,site}.dat` that `infra/conf` tests need.
`testing/gates.sh <unit|vless|smux|xhttp|race>` runs a tier below with these
flags and keeps a log per tier. Process matrices find sing-box and Mihomo next
to the checkout or the main checkout, or through `SING_BOX_E2E_BIN` and
`MIHOMO_E2E_BIN`; a matrix that cannot run is a blocker, not a skip.

### VLESS TCP and REALITY

```sh
go test ./transport/internet/reality ./proxy ./proxy/vless/... ./infra/conf \
  -count=1 -timeout 300s
go test -race ./transport/internet/reality ./proxy ./proxy/vless/... \
  -count=1 -timeout 300s
go test -gcflags=all=-d=checkptr=2 \
  ./transport/internet/reality ./proxy ./proxy/vless/inbound \
  ./proxy/vless/outbound -count=1 -timeout 300s
go vet ./transport/internet/reality ./proxy ./proxy/vless/...
go test -tags 'integration http2legacy' ./common/singmux \
  -run '^TestVLESSTCPProcessMatrix/' -count=3 -timeout 20m -v
```

The process gate is 3 clients × 2 security modes × 2 flow modes × 3 runs:
36/36 executions must pass.

### SMUX

```sh
go test ./common/singmux/... ./common/mux ./app/proxyman/outbound ./infra/conf \
  -timeout 300s
go test -race ./common/singmux/... ./common/mux -timeout 300s
go test -cover ./common/singmux/internal/mplsmux -timeout 300s
go test -tags 'integration http2legacy' ./common/singmux \
  -run '^TestSMUXProcessInteropMatrix$' -count=1 -timeout 20m -v
```

The SMUX process matrix is 3 clients × 2 carriers × 2 payload networks ×
2 padding modes: 24/24 Xray-server executions must pass.

Run the stress, reconnect, performance, and 50-cycle hardening commands from
`common/singmux/TESTING.md` when mux production code changes.

### Repository-wide

- Run `go test ./... -count=1 -timeout 2h` when the scope justifies it. Some
  upstream tests contact external services; report an external failure exactly
  and do not classify it as success or hide it with retries.
- A known unrelated warning/failure is not authority to add another. Record
  the existing evidence and keep all changed packages green.

## Linux server and network gates

- Build Linux/amd64 with `CGO_ENABLED=0`, `GOAMD64=v1`, `-trimpath`,
  `-tags http2legacy`, and the release linker flags. Verify `file`,
  `sha256sum`, and `go version -m`.
- For load work, test TLS/no-flow, TLS/Vision, REALITY/no-flow, and
  REALITY/Vision independently. Record throughput, p50/p95/p99 latency, CPU,
  RSS, GC, goroutines, threads, and file descriptors.
- Run a soak and restart/reconnect cycles for changes affecting lifecycle,
  concurrency, pooling, timeouts, or dispatch.
- Capture Linux interface and TCP counters before and after; never clear them.
  Fail on unexplained positive deltas in errors, drops, CRC/frame/FIFO/carrier
  errors, collisions, link flaps, retransmits, or resets.
- The authoritative VLESS and SMUX release gate is
  `testing/release/structural_presence.sh`, documented in
  `common/singmux/TESTING.md`.

## E2E and benchmark hygiene

- Start a real local Xray server and the selected real Xray, sing-box, or
  Mihomo client. Local echo servers, DNS/upstream fixtures, and REALITY cover
  targets are supporting services, not alternative proxy-server implementations.
  Do not replace the mandatory compatibility gate with mocks.
- Protect the maintainer's active host networking. Treat running NetBird and
  Mihomo processes, services, interfaces, routes, firewall rules, DNS settings,
  and configurations as user-owned. Use separate test processes, loopback or an
  isolated network namespace, and temporary configurations.
- Never stop, restart, reconfigure, replace, or kill the working NetBird or
  Mihomo instances, and never alter their host routes, DNS, firewall, or TUN
  state, unless the maintainer explicitly authorizes the exact action.
- Use temporary directories, loopback listeners, generated test certificates,
  explicit deadlines, behavior-based readiness, and cleanup registered before
  the assertion phase.
- Log server and client output on failure without leaking secrets.
- Exclude process build/startup and warm-up from timed benchmark regions.
- Bound fixed-connection benchmarks to avoid ephemeral-port exhaustion and
  TIME_WAIT distortion. Do not raise port limits to conceal a leaking test.
- Do not run performance comparisons concurrently with builds, race tests, or
  other load.

## Dependencies and licensing

- Search the existing tree before adding a dependency. Prefer the standard
  library and existing internal packages.
- Do not add a third-party mux dependency, import SagerNet, MetaCubeX, Hashicorp,
  or another mux implementation from mux production code, or copy GPL source
  into this repository.
- For permitted MPL-derived code, preserve the original license notices and
  record provenance. A rewrite is behavior-driven, does not silently change
  the wire protocol, and stays independently reviewable.
- Run the dependency-ban tests whenever mux imports or `go.mod` change.
- Do not update unrelated dependencies during a protocol or performance pass.

## Git and workspace discipline

- Treat a dirty worktree as user-owned. Do not reset, delete, format, stage, or
  rewrite unrelated files.
- Stage explicit paths only. Inspect `git diff --cached --check`, the staged
  name list, and staged statistics before committing.
- Commit only when explicitly requested. Use a focused imperative subject such
  as `perf(vless): ...`, `fix(reality): ...`, or `test(singmux): ...`.
- Name branches with a `fix/`, `feat/`, `perf/`, `test/`, `docs/`, `chore/`,
  `ci/`, or `build/` prefix. Never push a tool- or host-prefixed name.
- Pass `-R Jolymmiles/Xray-core` to every `gh` command; the default repository
  is upstream XTLS.
- Contributor PRs come from sibling forks of XTLS, so pushing to their
  branches returns 403 even with maintainer edits enabled. Push the fix to an
  `origin` branch and open a follow-up PR.
- An upstream sync is its own PR. Merging upstream ports fork regression tests
  onto rewritten code instead of deleting them.
- Every PR gets an independent review before merge.
- Do not commit build artifacts, temporary profiles, logs, local IDE state,
  `.codex`, graph output, or unrelated documentation.
- Never amend, rebase, force-push, or discard maintainer work without explicit
  authorization.

## Agent roles

The implementer is the agent that writes the code (Claude Opus by default). It
works with three helper roles. A run whose task prompt assigns one of these
roles performs that role's brief instead of the implementer duties, answers
the implementer directly, and starts sub-agents only where its brief allows;
every other rule in this file still applies to it.

| Role | Model | Tool |
| --- | --- | --- |
| `second-opinion` | GPT-6.1-Sol | T3 `delegate_task` |
| `code-reviewer` | GPT-6.1-Sol | T3 `delegate_task` with `"role": "review"` |
| `explorer` | Claude Haiku 5.5 | Agent tool `general-purpose`, `model: haiku` |

Dispatch both GPT roles with these `delegate_task` parameters:

```json
{
  "target": {
    "providerInstanceId": "codex",
    "model": "gpt-6.1-sol",
    "options": {"reasoningEffort": "high"}
  },
  "mode": "wait",
  "timeoutMs": 1800000,
  "clientRequestId": "<topic>-<role>-<round>"
}
```

A delegated task starts without the implementer's conversation, so its prompt
names the role and carries every fact the role needs. After `waitTimedOut`,
collect the answer with `task_status`. When the T3 tools are unavailable, the
final report states which consultation or review did not run.

### second-opinion

Consult it before committing to a choice you doubt, in particular when:

- two designs are plausible and differ in wire bytes, observable traffic
  shape, resource ownership, or configuration surface;
- an upstream behavior, specification, or test failure admits more than one
  reading;
- the plan would depart from a rule in this file.

Scope, priority, and product-behavior questions belong to the maintainer. The
prompt states the question, the constraints, each option with your current
leaning and its reason, and the evidence so far. The second opinion reads the
code it needs, leaves the worktree untouched (scratch experiments go to a
temporary directory), and returns a recommendation, its reasoning and
evidence, the main risk, and what would change its answer. The implementer
owns the decision; the final report names every safety, protocol, or
camouflage point where it overruled the second opinion.

### code-reviewer

It is the reviewer of the `xray-pr-review` skill: findings, severity, gates,
and the report follow `.claude/skills/xray-pr-review/SKILL.md`, and the
implementer launches, collects, and closes rounds by its `ORCHESTRATOR.md`.
Dispatch it once the change is complete and its targeted gates are green,
before the final report. A committed change gets the `ORCHESTRATOR.md` round
prompt. Work with no commit yet is reviewed in the live checkout while the
implementer waits: the prompt gives the request, the acceptance check, `HEAD`,
the gate results, and the ledger `/tmp/review/<topic>.md`, and the reviewer
reads `git diff HEAD` plus untracked files instead of pinning a worktree.
Repeat rounds until one reports no High or Medium finding; after three rounds,
hand the open findings to the maintainer.

### explorer

Hand it mechanical work whose result needs no judgement: running a test,
build, or gate command; locating files or symbols; collecting simple facts;
and many independent cheap checks or generations, fanned out in parallel. The
brief names the exact commands or questions and any path the explorer may
write; it changes only those paths. It reports each command verbatim with its
exit status and relevant output, and reports a failure as first observed,
without retrying it. The implementer interprets the results. Send each
follow-up to a fresh explorer; a resumed one can exhaust its context. Parallel
explorers never overlap a timed benchmark.

## Definition of done

A change is complete only when:

- the requested behavior is implemented and covered by a regression test;
- targeted unit tests, race, vet, and checkptr as applicable are green;
- all affected Xray/sing-box/Mihomo process cells pass without hidden retries;
- benchmarks show a repeatable improvement or no regression within the stated
  budget;
- Linux builds successfully, and Linux runtime/network evidence exists for a
  performance or release claim;
- baselines/specifications/testing docs are updated when behavior or
  measurements change;
- unrelated workspace changes remain untouched;
- every finding of the latest `code-reviewer` round has a disposition, no High
  finding is open, and a Medium finding stays open only when the maintainer
  deferred it;
- the final report lists exact commands, results, limitations, artifact hash,
  and any genuine blocker.

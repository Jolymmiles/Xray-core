# Xray-core fork development instructions

These instructions apply to the entire repository. More specific `AGENTS.md`
files may narrow them for a subtree but must not weaken the safety, licensing,
test, or compatibility gates defined here.

## Project direction

- Optimize and harden the Xray server first. Linux/amd64 is the release and
  performance target; Darwin is useful for development but is not evidence of
  Linux server capacity.
- Preserve protocol interoperability. Xray, sing-box, and Mihomo are mandatory
  external compatibility clients for changed VLESS, Trojan, REALITY, Vision,
  or mux paths.
- Prefer simple, reviewable changes. Do not mix several speculative
  optimizations into one pass.
- Communicate with the maintainer in Russian unless they request another
  language. Keep code, identifiers, commit messages, and repository
  documentation in English unless an existing file establishes otherwise.

## Intentional fork behavior

- REALITY client-version bounds are operator-configurable and carry no built-in
  default. `minClientVer` and `maxClientVer` are parsed and reach the REALITY
  handshake when the operator sets them; when either is omitted it stays nil and
  that side of the gate rejects nobody. Do not reintroduce upstream's implicit
  `26.3.27` minimum. Covered by `infra/conf/reality_clientver_test.go` and
  `transport/internet/reality/clientver_test.go`.
- The maintained SMUX implementation is the in-tree stack under
  `common/singmux`. Mux-related production code must not directly import
  SagerNet, MetaCubeX, Hashicorp, or another mux implementation.
- Preserve MPL-2.0 notices and provenance for MPL-derived code. Do not copy GPL
  files into this repository. A rewrite must be behavior-driven and must not
  silently change the wire protocol.
- SMUX is the active mux scope. Do not add YAMUX or H2MUX work unless the
  maintainer explicitly requests it.

## Before changing code

1. Read `git status --short` and the relevant recent commits. Assume unrelated
   tracked and untracked changes belong to the maintainer.
2. Read the package tests, protocol specification, baseline, and testing guide
   before modifying a protocol or performance path.
3. State the exact server path, invariant, acceptance check, and bounded work
   item. One measured hot spot or one behavior change is a normal pass.
4. Record a reproducible baseline before optimizing. Include the command,
   source revision/dirty state, Go version, host OS/architecture, and multiple
   samples.

Relevant documents:

- `proxy/vless/TESTING.md` — VLESS TCP TLS/REALITY server release methodology.
- `proxy/vless/BASELINE.md` — VLESS behavior and performance baselines.
- `common/singmux/SPEC.md` and `common/singmux/ENGINE_SPEC.md` — SMUX protocol
  and engine contracts.
- `common/singmux/TESTING.md` and `common/singmux/BASELINE.md` — SMUX release
  gates and measurements.

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

- Run `gofmt` on every changed Go file.
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
- Run at least five samples; use medians and inspect variance. Compare the same
  commit conditions, Go version, CPU governor, host load, and kernel settings.
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

### VLESS TCP and REALITY

```sh
go test ./transport/internet/reality ./proxy ./proxy/vless/... ./infra/conf \
  -count=1
go test -race ./transport/internet/reality ./proxy ./proxy/vless/... \
  -count=1
go test -gcflags=all=-d=checkptr=2 \
  ./transport/internet/reality ./proxy ./proxy/vless/inbound \
  ./proxy/vless/outbound -count=1
go vet ./transport/internet/reality ./proxy ./proxy/vless/...
go test -tags integration ./common/singmux \
  -run '^TestVLESSTCPProcessMatrix/' -count=3 -v
```

The process gate is 3 clients × 2 security modes × 2 flow modes × 3 runs:
36/36 executions must pass.

### SMUX

```sh
go test ./common/singmux/... ./common/mux ./app/proxyman/outbound ./infra/conf
go test -race ./common/singmux/... ./common/mux
go test -cover ./common/singmux/internal/mplsmux
go test -tags integration ./common/singmux \
  -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
```

Run the stress, reconnect, performance, and 50-cycle hardening commands from
`common/singmux/TESTING.md` when mux production code changes.

### Repository-wide

- Run `go test ./... -count=1` when the scope justifies it. Some upstream tests
  contact external services; report an external failure exactly and do not
  classify it as success or hide it with retries.
- A known unrelated warning/failure is not authority to add another. Record
  the existing evidence and keep all changed packages green.

## Linux server and network gates

- Build Linux/amd64 with `CGO_ENABLED=0`, `GOAMD64=v1`, `-trimpath`, and the
  release linker flags. Verify `file`, `sha256sum`, and `go version -m`.
- For load work, test TLS/no-flow, TLS/Vision, REALITY/no-flow, and
  REALITY/Vision independently. Record throughput, p50/p95/p99 latency, CPU,
  RSS, GC, goroutines, threads, and file descriptors.
- Run a soak and restart/reconnect cycles for changes affecting lifecycle,
  concurrency, pooling, timeouts, or dispatch.
- Capture Linux interface and TCP counters before and after; never clear them.
  Fail on unexplained positive deltas in errors, drops, CRC/frame/FIFO/carrier
  errors, collisions, link flaps, retransmits, or resets.
- Use `proxy/vless/TESTING.md` as the authoritative VLESS release checklist.

## E2E and benchmark hygiene

- Start real local Xray, sing-box, and Mihomo processes. Do not replace the
  mandatory compatibility gate with mocks.
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
- Do not add a third-party mux dependency or copy GPL mux source.
- For permitted MPL-derived code, preserve the original license notices and
  record provenance. Keep later rewrites independently reviewable.
- Run the dependency-ban tests whenever mux imports or `go.mod` change.
- Do not update unrelated dependencies during a protocol or performance pass.

## Git and workspace discipline

- Treat a dirty worktree as user-owned. Do not reset, delete, format, stage, or
  rewrite unrelated files.
- Stage explicit paths only. Inspect `git diff --cached --check`, the staged
  name list, and staged statistics before committing.
- Commit only when explicitly requested. Use a focused imperative subject such
  as `perf(vless): ...`, `fix(reality): ...`, or `test(singmux): ...`.
- Do not commit build artifacts, temporary profiles, logs, local IDE state,
  `.codex`, graph output, or unrelated documentation.
- Never amend, rebase, force-push, or discard maintainer work without explicit
  authorization.

## Release workflow and format

This fork stamps each release as UTC `year.month.day-HHMM`. That string is
the panel version, the git tag, and the GitHub release name.

### Version identity

- Take the current UTC date and time. Write it as `YY.M.D-HHMM` with a
  hyphen before the time so the string is valid semver. Example: 25 Aug 2026
  14:57 UTC → `26.8.25-1457`.
- Put year, month, and day in `Version_x`, `Version_y`, and `Version_z`.
  Put `HHMM` in `versionHHMM`. `core.Version()` must return
  `fmt.Sprintf("%v.%v.%v-%04d", Version_x, Version_y, Version_z, versionHHMM)`.
- The git tag is `v` plus that string (`v26.8.25-1457`). The GitHub release
  title is `Xray-core v26.8.25-1457`. Panel output, tag, and title must match.
- REALITY still sends the three numeric bytes `Version_x/y/z`. Time is
  display-only.
- One canonical release per stamp. Public release text is English. Publish on
  `origin` (`Jolymmiles/Xray-core`), not upstream. Pass `-R Jolymmiles/Xray-core`
  to `gh` so the default XTLS repo is not used.

### Cut a release

1. Fetch `origin` and `upstream` including tags. Merge the reviewed branch
   plus latest `origin/main` and `upstream/main` into canonical `main`.
   If upstream already tagged the same `vYY.M.D` triple, resolve that
   collision before tagging. Completion: `git rev-parse main` is the release
   commit and includes upstream.
2. Stamp `core/core.go` to the current UTC `YY.M.D-HHMM`. Update
   `core/version_test.go` to the same string. Commit the bump. Completion:
   `core.Version()` and `xray version` print that string, and
   `TestVersionFollowsYearMonthDayHHMM` is green.
3. Run the applicable unit, race, vet, checkptr, interoperability, Linux
   build, and Tests and Checkings gates, including `check-proto`. Protobuf
   headers must match `core/config.pb.go` (`protoc-gen-go v1.36.11`,
   `protoc v6.33.5`); regenerate with that toolchain via
   `go run ./infra/vprotogen` after installing those tools. Completion:
   targeted gates are green or a real external failure is recorded as such.
4. Push `main`, then create an annotated tag `vYY.M.D-HHMM` and push the
   tag. Completion: `origin/main`, the tag commit, and `HEAD` are the same
   SHA.
5. Create the GitHub Release from that tag with title
   `Xray-core vYY.M.D-HHMM` and let `.github/workflows/release.yml` upload
   assets. Completion: every required matrix job is green and the ZIP plus
   `.dgst` files are on the release. Do not upload replacement binaries by
   hand.

Do not move a published tag unless the maintainer explicitly authorizes
rewriting it. If they ask to replace a release, delete the GitHub release and
its tag, then cut a new stamp from current UTC rather than reusing the old
HHMM.

Release notes must be substantive, not just links or an autogenerated commit
list:

1. `## Highlights` — the user-visible outcome and the most important changes.
2. `## Fork fixes` — correctness, security, performance, and regression fixes
   maintained by this fork, including root cause and impact where useful.
3. `## Upstream changes` — the upstream version merged and its relevant
   user-visible changes.
4. `## Compatibility notes` — intentional fork behavior, configuration or
   protocol implications, and upgrade concerns.
5. `## Validation` — the meaningful tests and release gates that passed.

Keep the notes concise but specific. Name affected protocols and subsystems,
explain what was fixed, and state any intentional behavior that differs from
upstream. Never describe an unverified performance or reliability claim as
established fact.

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
- the final report lists exact commands, results, limitations, artifact hash,
  and any genuine blocker.

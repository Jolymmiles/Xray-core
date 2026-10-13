# Orchestrating review rounds

For the agent that launches reviewers and collects their results. Reviewers follow [SKILL.md](SKILL.md).

## Before a round

1. Get the SHAs (GH.md): `base`, `head`, and `delta` = previous reviewed `head`..new `head` (none in round 1). Pass SHAs, never branch names; the implementer's branch moves.
2. Create the ledger once: `mkdir -p /tmp/review && [ -e /tmp/review/pr<N>.md ] || printf '# PR <N> review ledger\n' > /tmp/review/pr<N>.md`.
3. Own the watch. `watch_pull_request` is yours, one per PR. Reviewers get no PR linkage. Call `unwatch_pull_request` before handing the thread back to the maintainer.

## Round prompt

Fill and send; add nothing the skill already states.

```
Use the xray-pr-review skill. Read-only review of PR #<N> (Jolymmiles/Xray-core), round <R>.
base:            <BASE_SHA>
head:            <HEAD_SHA>
delta:           <PREV_HEAD_SHA>..<HEAD_SHA>   (round 1: none)
ledger:          /tmp/review/pr<N>.md
prior findings:  /tmp/review/pr<N>.md          (round 1: none)
focus:           <areas and risks, or "full diff">
claims to verify: <items called known, accepted or pre-existing, or "none">
```

## Collect

`task_status` returns only a task's first result, so later turns are invisible through it. On ANY terminal or failed state (completed, failed, interrupted, timed out, an API error such as an HTTP 400 rejection), and before launching the next round or reporting:

1. Read the ledger.
2. Read the reviewer's thread with `t3_thread_read` (page with `afterPosition`) and the output of every sub-agent it spawned.
3. Append to the ledger any finding present in an output but missing from it, tagged `(recovered from <source>)`.

Done when every finding in any output is in the ledger. A failed reviewer is relaunched for the same round, on another model if the failure was an API rejection, with the ledger as `prior findings`; partial work is never discarded.

## Close a round

Append one line per finding: `DISPOSITION R<r>-<n>: fixed in <sha> | rejected: <reason> | deferred: <who>`. The fix commit range becomes the next round's `delta`. Done when every ledger id has a disposition.

## Writing to the PR

Orchestrator only. A review or comment posted on GitHub carries the findings, each with the reproduction needed to act on it: a failing input, a negative control, a benchmark table behind a request. The list of gates you re-ran goes in the report to the maintainer, never in the PR (maintainer decision 2026-10-07).

`gh pr edit` fails on the Projects (classic) deprecation; patch through the API (syntax from `gh api --help`, not run during authoring):

```sh
gh api -X PATCH repos/Jolymmiles/Xray-core/pulls/<N> -F body=@/tmp/review/pr<N>-body.md
```

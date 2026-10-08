# GitHub and git calls for PR review

Verified with gh 2.46.0 and git 2.47 against this repo. All calls are read-only.

## Always name the repo

A bare `gh pr list` or `gh pr view` in a clone of this fork resolves to upstream `XTLS/Xray-core` (here it returned upstream PR #7102). Pass `-R Jolymmiles/Xray-core` on every call, or `-R XTLS/Xray-core` when you mean upstream.

## Snippets

```sh
# PR facts; --json is required (see gotchas)
gh pr view <N> -R Jolymmiles/Xray-core --json number,title,state,isDraft,body,baseRefName,headRefName,headRefOid,isCrossRepository,maintainerCanModify,changedFiles,mergeStateStatus

# base and head SHAs (gh pr view --json has no baseRefOid)
gh api repos/Jolymmiles/Xray-core/pulls/<N> --jq '{base: .base.sha, head: .head.sha}'

# linked issues; usually empty because the fork has issues disabled
gh api graphql -f query='query($n:Int!){repository(owner:"Jolymmiles",name:"Xray-core"){pullRequest(number:$n){closingIssuesReferences(first:20){nodes{number title state}}}}}' -F n=<N>

# upstream issue cited as XTLS/Xray-core#NNNN
gh issue view <NNNN> -R XTLS/Xray-core --json title,state,body,comments

# conversation
gh pr view <N> -R Jolymmiles/Xray-core --json comments,reviews
gh api repos/Jolymmiles/Xray-core/pulls/<N>/comments --paginate      # inline review comments
gh api repos/Jolymmiles/Xray-core/issues/<N>/comments --paginate     # PR-level comments

# changed files (prefer local git diff on pinned SHAs)
gh pr diff <N> -R Jolymmiles/Xray-core --name-only

# CI
gh pr checks <N> -R Jolymmiles/Xray-core                  # text: name, state, elapsed, url
gh run list -R Jolymmiles/Xray-core --commit <HEAD> --json databaseId,event,workflowName,conclusion,status
gh run view <RUN_ID> -R Jolymmiles/Xray-core --json jobs --jq '.jobs[] | {databaseId,name,conclusion}'
gh api repos/Jolymmiles/Xray-core/actions/jobs/<JOB_ID>/logs | grep -E -- '--- FAIL|^FAIL|panic:'
```

## Gotchas

- `gh pr view --json` has no `baseRefOid`; use the pulls API above.
- `gh pr checks` has no `--json` in this gh; parse the text or use `gh run list`.
- Plain `gh pr view <N>`, `gh pr view --comments`, `gh issue view --comments` and `gh pr edit` fail with "Projects (classic) is being deprecated". Use `--json` fields without `projectCards`/`projectItems`; edits go through `gh api -X PATCH` (orchestrator only, see ORCHESTRATOR.md).
- `gh run view --log-failed` can print nothing or "log not found" for a failed run. Use the job logs API above; find the job id with `gh run view <RUN_ID> --json jobs`.
- Same-repo PR: `Tests and Checkings` jobs show SKIPPED on the `pull_request` event because the `if:` in `.github/workflows/test.yml` runs them on `push`. The result is the `push` run on the head SHA (`gh run list --commit <HEAD>` shows both). SKIPPED is neither a pass nor missing CI.
- Fork PR: the same `if:` runs the jobs on `pull_request` (PRs #17 and #23 got all four), but a head SHA can have no run at all (PR #13). No run for the head SHA means no CI evidence: run the gates yourself and say so.
- `./main` is a directory, so `git log main` and `git diff main` abort with "ambiguous argument 'main': both revision and filename". Use a SHA, `refs/heads/main`, `origin/main`, or `git log main --`. `main..HEAD` ranges work. Local `refs/heads/main` can lag `origin/main`; take the base from the round prompt.
- `git diff --check` fails on trailing whitespace in vendored `third_party/` bytes that must stay identical to upstream. Use `git diff --check <BASE>...<HEAD> -- . ':!third_party'`.
- `git fetch origin <sha>` rewrites `FETCH_HEAD` in the checkout you run it from; `--no-write-fetch-head` avoids that.

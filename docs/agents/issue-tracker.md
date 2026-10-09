# Issue tracker: GitHub pull requests (Jolymmiles/Xray-core)

This fork is `Jolymmiles/Xray-core`; upstream is `XTLS/Xray-core`. Issues are disabled on the fork (`gh issue list -R Jolymmiles/Xray-core` fails with "repository has disabled issues"), so the spec for a change is its pull request body plus any issue the PR links.

## Always pass -R

A bare `gh` command in a clone of this fork resolves to upstream. Name the repository on every call: `-R Jolymmiles/Xray-core` for the fork, `-R XTLS/Xray-core` only for upstream issues and PRs. Details and failing calls: `.claude/skills/xray-pr-review/GH.md`.

## The spec for a change

- **PR body**: `gh pr view <number> -R Jolymmiles/Xray-core --json title,body,baseRefName,headRefName,headRefOid`
- **Linked issues**: `gh api graphql -f query='query($n:Int!){repository(owner:"Jolymmiles",name:"Xray-core"){pullRequest(number:$n){closingIssuesReferences(first:20){nodes{number title state}}}}}' -F n=<number>`
- **Upstream issues** cited as `XTLS/Xray-core#NNNN`: `gh issue view <NNNN> -R XTLS/Xray-core --json title,state,body,comments`
- **PR discussion**: `gh pr view <number> -R Jolymmiles/Xray-core --json comments,reviews`

Use `--json`: plain `gh pr view` and `--comments` fail with the Projects (classic) deprecation error.

## Coding standards

The standards are the named sections of `AGENTS.md`:

- Mandatory TDD workflow
- Go implementation standards
- Protocol invariants
- Performance workflow
- Required test tiers
- E2E and benchmark hygiene
- Dependencies and licensing
- Git and workspace discipline
- Definition of done

`docs/FORK.md` lists behavior that differs from upstream on purpose; it overrides upstream expectations.

## When a skill says "publish to the issue tracker"

There is no tracker. Put the text in the PR body.

## When a skill says "fetch the relevant ticket"

Fetch the PR body and linked issues as above.

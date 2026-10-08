---
name: release
description: Cut an Xray-core fork release stamped UTC YY.M.D-HHMM, from gates to a published GitHub Release.
disable-model-invocation: true
---

# Release

The fork stamps each release as UTC `YY.M.D-HHMM`. That string is the panel version,
the git tag (`v` prefix), and the GitHub release name. Run every step in order and
stop at the first failed completion criterion.

## Version identity

- `date -u +'%y.%-m.%-d-%H%M'` prints the stamp, e.g. 7 Oct 2026 23:04 UTC gives
  `26.10.7-2304`. The hyphen before the time keeps it valid semver.
- `Version_x`, `Version_y`, `Version_z` in `core/core.go` hold year, month, day;
  `versionHHMM` holds `HHMM`. `core.Version()` returns
  `fmt.Sprintf("%v.%v.%v-%04d", Version_x, Version_y, Version_z, versionHHMM)`.
- Tag `v26.10.7-2304`; release title `Xray-core v26.10.7-2304`. Panel output, tag, and
  title match.
- REALITY sends only the three numeric bytes `Version_x/y/z`; the time is display-only.
- One canonical release per stamp. Release text is English. Publish on `origin`
  (`Jolymmiles/Xray-core`), never upstream, and pass `-R Jolymmiles/Xray-core` to every
  `gh` call so the default XTLS repo is not used.

## Steps

1. **Preflight.** Completion: all four pass.
   - `gh auth status` shows account `Jolymmiles`, and
     `gh api repos/Jolymmiles/Xray-core --jq .permissions.push` prints `true`
     (a read-only account cannot publish).
   - `git config user.email` and `git log -1 --format=%ae` end in
     `@users.noreply.github.com`; the personal address never reaches a release commit.
   - Actions is operational:
     `curl -fsS https://www.githubstatus.com/api/v2/components.json | jq -r '.components[] | select(.name=="Actions") | .status'`
     prints `operational`. Publishing during an outage left `releases/latest` at 404
     for about 75 minutes; during an outage apply the outage exception below or wait.
   - `git status --short` shows no unrelated changes you would carry into the release.

2. **Merge candidate.** Fetch `origin` and `upstream` with tags. Merge the reviewed
   branch and the latest `origin/main` into canonical `main`. An upstream sync lands
   as its own reviewed PR before the release, never inside it. If upstream already
   tagged the same `vYY.M.D` triple, resolve that collision first. Completion:
   `git rev-parse refs/heads/main` is the candidate and
   `git merge-base --is-ancestor upstream/main refs/heads/main` succeeds. Write
   `refs/heads/main`: `main` alone is ambiguous with the `./main` directory.

3. **Gates on the candidate, before stamping.** Run the applicable tiers from
   `AGENTS.md` "Required test tiers" (unit, race, vet, checkptr, the interop process
   matrices) plus the Linux build gate ("Linux server and network gates") and the
   checks of `Tests and Checkings` (`.github/workflows/test.yml`), including
   `check-proto`: protobuf headers must match `core/config.pb.go`
   (`protoc-gen-go v1.36.11`, `protoc v6.33.5`); regenerate with that toolchain through
   `go run ./infra/vprotogen`. `testing/release/structural_presence.sh standard` is the
   full local entrypoint. Completion: every applicable gate is green. Only a test that
   contacts an external service may instead have its failure recorded exactly
   (`AGENTS.md` "Repository-wide"); a failed process-matrix cell, race, vet or checkptr
   run blocks the stamp until a clean rerun passes. A gate fix lands before the stamp,
   so no stamp is spent on a candidate that still changes.

4. **Stamp.** Take the current UTC stamp and edit `core/core.go` (`Version_x/y/z`,
   `versionHHMM`) and `core/version_test.go` to the same string. Commit
   `chore(release): stamp version as YY.M.D-HHMM UTC`. Completion:
   `git diff --stat <candidate>..HEAD` lists only those two files;
   `go test ./core -run '^TestVersionFollowsYearMonthDayHHMM$' -count=1 -timeout 120s`
   is green; the Linux build gate builds; `go run ./main version` prints the stamp.
   This is all the stamp commit needs, because the candidate already passed the gates.

5. **Validate on `main` before any tag.** `git push origin refs/heads/main`.
   `Tests and Checkings` starts on the push. Start the pinned Linux gate (about 75 minutes) on the same commit:
   `gh workflow run pre-release-validation.yml -R Jolymmiles/Xray-core --ref main`.
   Find its run:
   `gh run list -R Jolymmiles/Xray-core -w pre-release-validation.yml -c $(git rev-parse refs/heads/main) --json databaseId,status,conclusion`.
   Wait with `gh run watch <id> -R Jolymmiles/Xray-core --exit-status` as a background
   command. Completion: `Pre-release Validation` and `Tests and Checkings` are both
   `success` for the release commit. A red run means no tag: read the failed job with
   `gh api repos/Jolymmiles/Xray-core/actions/jobs/<job id>/logs` (job ids from
   `gh run view <id> -R Jolymmiles/Xray-core --json jobs`; `--log-failed` can print
   nothing), fix through a PR, and restart at step 3 with a fresh stamp. A commit that
   lands on `main`
   after a validation run starts invalidates that run: validate the new head. The gate
   itself (`testing/release/structural_presence.sh linux`) is described in
   `common/singmux/TESTING.md`.

6. **Tag.** Create the annotated tag `vYY.M.D-HHMM` on the validated commit and push
   it. Completion: `origin/main`, the tag's commit, and `HEAD` are the same SHA
   (`git rev-parse refs/heads/main 'refs/tags/<TAG>^{commit}'`,
   `git ls-remote origin refs/heads/main 'refs/tags/<TAG>^{}'`).

7. **Publish as a prerelease.** Write the notes (format below) to a file outside the
   repository, then:
   `gh release create <TAG> -R Jolymmiles/Xray-core --verify-tag --prerelease --title "Xray-core <TAG>" --notes-file <file>`.
   Publishing, prerelease included, starts `.github/workflows/release.yml`, which builds
   and uploads the assets; never upload binaries by hand (outage exception below). Watch its run
   (`gh run list -R Jolymmiles/Xray-core -w release.yml -c <sha> --json databaseId,event,status,conclusion`,
   then `gh run watch ... --exit-status`). Completion: every matrix job is green and
   `gh release view <TAG> -R Jolymmiles/Xray-core --json assets --jq '[.assets[].name]'`
   lists `Xray-<name>.zip` and `Xray-<name>.zip.dgst` for every `<name>` the matrix in
   `.github/workflows/release.yml` builds (`linux-64` and `linux-arm64-v8a` today; the
   names come from `.github/build/friendly-filenames.json`), plus the bare `Xray-<name>`
   binary. A red job leaves the release a prerelease; report its cause to the
   maintainer before any rerun.

8. **Make it latest.** Download the linux-64 pair into a fresh directory
   (`gh release download <TAG> -R Jolymmiles/Xray-core -p 'Xray-linux-64.zip*' -D <dir>`),
   compare `sha256sum` of the ZIP with the sha256 line of its `.dgst`, and run the
   extracted `xray version` (it prints the stamp). Then
   `gh release edit <TAG> -R Jolymmiles/Xray-core --latest --prerelease=false`.
   Completion: `gh api repos/Jolymmiles/Xray-core/releases/latest --jq .tag_name`
   prints `<TAG>`. Report the artifact hash.

## Tags

- A published release's tag is never moved without the maintainer's explicit
  authorization. To replace a release, delete it and its tag
  (`gh release delete <TAG> -R Jolymmiles/Xray-core --cleanup-tag --yes`), then cut a
  new stamp from the current UTC time; the old `HHMM` is not reused.
- A pushed tag with no GitHub Release may be deleted
  (`git push origin :refs/tags/<TAG>`, `git tag -d <TAG>`; maintainer decision
  2026-10-06). Delete it at once; an orphan tag must not sit unnoticed.

## Outage exception

Maintainer decision 2026-10-05. Applies only while a GitHub Actions outage is confirmed
(githubstatus.com) and the maintainer approves that release. From a clean checkout of
the tag, run the exact `Build Xray`, geodata, README/LICENSE, `Create ZIP archive` steps
of `.github/workflows/release.yml`, upload every `Xray-<name>*` file the workflow would
attach with `gh release upload <TAG> -R Jolymmiles/Xray-core`, and add a "Release assets" paragraph
to the notes saying they were built by hand and why. After recovery run `release.yml`
through `gh workflow run release.yml -R Jolymmiles/Xray-core --ref <TAG>`,
download its `Xray-<name>` artifact with `gh run download`, and compare the sha256 of
its `xray` with the one in the uploaded ZIP. A mismatch goes to the maintainer.

## Release notes

Substantive, never links or an autogenerated commit list. Five sections, in order:

1. `## Highlights` — the user-visible outcome and the most important changes.
2. `## Fork fixes` — correctness, security, performance, and regression fixes this fork
   maintains, with root cause and impact where useful.
3. `## Upstream changes` — the upstream version merged and its relevant user-visible
   changes.
4. `## Compatibility notes` — intentional fork behavior (`docs/FORK.md`), configuration
   or protocol implications, upgrade concerns, and the "Release assets" paragraph when
   the outage exception applied.
5. `## Validation` — the gates that passed, with the `Pre-release Validation` run URL.

Name affected protocols and subsystems, say what was fixed, and state intentional
differences from upstream. A performance or reliability claim without measurement stays
out.

#!/usr/bin/env bash
# Prepare a fresh git worktree for the test suites.
#
# resources/geoip.dat and resources/geosite.dat are gitignored, so a new
# worktree lacks them and the infra/conf, app/router and common/geodata tests
# panic. This script links them from the main checkout, which it finds through
# the shared git directory. It is idempotent and never touches the network.
#
# usage: testing/setup-worktree.sh [--copy]
#   --copy  copy the files instead of symlinking them

set -euo pipefail

mode=link
case "${1:-}" in
"") ;;
--copy) mode=copy ;;
*)
	echo "usage: $0 [--copy]" >&2
	exit 2
	;;
esac

root="$(git rev-parse --show-toplevel)"
common="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)"
if [[ "$(basename "$common")" != .git ]]; then
	echo "git common directory $common is not <checkout>/.git; cannot locate the main checkout" >&2
	exit 1
fi
main="$(dirname "$common")"

mkdir -p "$root/resources"
failed=0
for asset in geoip.dat geosite.dat; do
	from="$main/resources/$asset"
	to="$root/resources/$asset"
	# The main checkout itself, or a link from an earlier run; --copy replaces
	# such a link with a copy. An empty file is missing data, not in place.
	if [[ "$from" -ef "$to" && -s "$to" ]] && [[ "$mode" == link || ! -L "$to" ]]; then
		echo "ok      $asset (already in place)"
		continue
	fi
	# Keep a worktree's own non-empty copy, even when the main checkout has
	# none; replace anything else, including empty files and dangling or stale
	# symlinks.
	if [[ -s "$to" && ! -L "$to" ]]; then
		echo "ok      $asset (kept the existing file)"
		continue
	fi
	if [[ ! -s "$from" ]]; then
		echo "missing $from; place the file there once, this script does not download it" >&2
		failed=1
		continue
	fi
	if [[ "$mode" == copy ]]; then
		cp -f "$from" "$to.tmp"
		mv -f "$to.tmp" "$to"
		echo "copied  $asset <- $from"
	else
		ln -sfn "$from" "$to"
		echo "linked  $asset -> $from"
	fi
done

if ((failed)); then
	exit 1
fi
if ! git -C "$root" check-ignore -q resources/geoip.dat; then
	echo "warning: resources/geoip.dat is not gitignored here; do not commit it" >&2
fi

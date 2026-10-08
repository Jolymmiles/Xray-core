#!/usr/bin/env bash
# Run the test tiers named in AGENTS.md "Required test tiers", in
# common/singmux/TESTING.md and in transport/internet/splithttp/BASELINE.md.
#
# Every command runs with GOFLAGS=-tags=http2legacy (the tag every release is
# built with) and an explicit -timeout. A tier's output goes to one log; the
# script prints one line per step and a pass/fail table at the end, and exits
# non-zero if any tier failed. Failing steps do not stop the tier.
#
# The interop peers (sing-box, Mihomo) are found by the test harness next to
# the checkout or next to the main checkout, so a worktree needs no
# environment. Exported XRAY_E2E_BIN, SING_BOX_E2E_BIN and MIHOMO_E2E_BIN
# still replace the matching build.

set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: testing/gates.sh <tier>... | all

tiers:
  unit   format check, go vet ./..., go test -short ./...      (iteration)
  vless  VLESS TCP and REALITY: tests, race, checkptr, vet, process matrix (36 cells)
  smux   SMUX: tests, race, checkptr, coverage, process matrix (24 cells)
  xhttp  XHTTP: splithttp and Mux.Cool tests, race, vet, process gates
  race   only the race commands of vless, smux and xhttp
  all    unit vless smux xhttp (their race steps are included)

GATES_LOG_DIR sets the log directory (default: a new directory under $TMPDIR).
EOF
}

if (($# == 0)); then
	usage
	exit 2
fi

# Read the arguments first: help and a mistyped tier need no test setup.
tiers=()
for argument in "$@"; do
	case "$argument" in
	unit | vless | smux | xhttp | race) tiers+=("$argument") ;;
	all) tiers+=(unit vless smux xhttp) ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown tier: $argument" >&2
		usage
		exit 2
		;;
	esac
done

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# An explicit tags flag on a go command replaces the tags in GOFLAGS, so every
# command below that names its own tags lists http2legacy as well.
export GOFLAGS=-tags=http2legacy

# The geodata the infra/conf tests read is gitignored; a fresh worktree lacks it.
testing/setup-worktree.sh >/dev/null

log_dir="${GATES_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/xray-gates.XXXXXX")}"
mkdir -p "$log_dir"

tier_log=
failed_steps=()

# step <label> <command...>: run a command, append its output to the tier log
# and record whether it passed.
step() {
	local label=$1 started=$SECONDS
	shift
	printf '\n### %s\n$ %s\n' "$label" "$*" >>"$tier_log"
	if "$@" >>"$tier_log" 2>&1; then
		printf '  ok    %-34s %5ds\n' "$label" $((SECONDS - started))
	else
		printf '  FAIL  %-34s %5ds\n' "$label" $((SECONDS - started))
		failed_steps+=("$label")
	fi
}

# Steps shared by a tier and by the race tier.
race_vless() { step "race vless" go test -race ./transport/internet/reality ./proxy ./proxy/vless/... -count=1 -timeout 30m; }
race_smux() { step "race smux" go test -race ./common/singmux/... ./common/mux -count=1 -timeout 30m; }
race_xhttp() { step "race splithttp" go test -race ./transport/internet/splithttp -count=1 -timeout 30m; }

tier_unit() {
	step "format (vformat)" go run ./infra/vformat/main.go -mode check -pwd ./
	step "vet ./..." go vet ./...
	step "test -short ./..." go test -short -count=1 -timeout 30m ./...
}

tier_vless() {
	step "test" go test ./transport/internet/reality ./proxy ./proxy/vless/... ./infra/conf -count=1 -timeout 30m
	race_vless
	step "checkptr" go test -gcflags=all=-d=checkptr=2 ./transport/internet/reality ./proxy ./proxy/vless/inbound ./proxy/vless/outbound -count=1 -timeout 30m
	step "vet" go vet ./transport/internet/reality ./proxy ./proxy/vless/...
	step "process matrix (36 cells)" go test -tags 'integration http2legacy' ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -timeout 60m -v
}

tier_smux() {
	step "test" go test ./common/singmux/... ./common/mux ./app/proxyman/inbound ./app/proxyman/outbound ./infra/conf -count=1 -timeout 30m
	race_smux
	step "checkptr" go test -gcflags=all=-d=checkptr=2 ./common/singmux ./app/proxyman/inbound -count=1 -timeout 30m
	step "coverage mplsmux" go test -cover ./common/singmux/internal/mplsmux -count=1 -timeout 10m
	step "process matrix (24 cells)" go test -tags 'integration http2legacy' ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -timeout 60m -v
}

tier_xhttp() {
	step "test" go test ./transport/internet/splithttp ./common/mux -count=1 -timeout 30m
	race_xhttp
	step "vet" go vet ./transport/internet/splithttp
	# sing-box has no XHTTP client; BASELINE.md stubs it out so it is not built.
	step "process gates" env "SING_BOX_E2E_BIN=${SING_BOX_E2E_BIN:-$(type -P true)}" \
		go test -tags 'integration http2legacy' ./common/singmux -run '^(TestXHTTPFlowProcess|TestXHTTPMuxCoolProcess)$' -count=1 -timeout 30m -v
}

tier_race() {
	race_vless
	race_smux
	race_xhttp
}

echo "logs: $log_dir"
echo "GOFLAGS=$GOFLAGS"
results=()
overall=0
for tier in "${tiers[@]}"; do
	tier_log="$log_dir/$tier.log"
	: >"$tier_log"
	failed_steps=()
	started=$SECONDS
	echo "== $tier"
	"tier_$tier"
	elapsed=$((SECONDS - started))
	if ((${#failed_steps[@]} == 0)); then
		results+=("$(printf '%-7s PASS  %6ds  %s' "$tier" "$elapsed" "$tier_log")")
	else
		overall=1
		results+=("$(printf '%-7s FAIL  %6ds  %s\n          failed: %s' "$tier" "$elapsed" "$tier_log" "$(
			IFS=,
			echo "${failed_steps[*]}"
		)")")
	fi
done

echo
echo "tier    result  time    log"
printf '%s\n' "${results[@]}"
exit "$overall"

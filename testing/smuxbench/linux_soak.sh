#!/usr/bin/env bash
# linux_soak.sh — Standards-3 Linux goroutine/RSS soak gate for singmux.
#
# Owned by Builder 1 (R6). Touches only this file and LINUX_SOAK.md.
# Does not modify any production or settled package source.
#
# Acceptance (task-ms4rgh43):
#   1. GOOS=linux build of the singmux packages must pass.
#   2. Under a Linux container (docker run golang…), run the singmux suite
#      with -race -count=20 and capture goroutine + RSS deltas.
#   3. If Docker/Linux is unavailable, exit non-zero with the exact operator
#      command — never fabricate numbers.
#
# Canonical package-manifest bracket (D66, freeze value):
#   manifest.sh 52 common/singmux common/singmux/internal/mplsmux
#   → ebbc91d414c185bb79df2ef496a89381
# (hash+path lines, exact file-count guard; not the older hashes-only form.)
#
# Usage (from repository root):
#   ./testing/smuxbench/linux_soak.sh
#   ./testing/smuxbench/linux_soak.sh --count 5          # diagnostic only
#   ./testing/smuxbench/linux_soak.sh --skip-docker      # host compile only
#   COUNT=20 IMAGE=golang:1.26-bookworm ./testing/smuxbench/linux_soak.sh

set -euo pipefail

# D66 freeze default (hash+path form, 52 files). Override with EXPECTED_MANIFEST=.
EXPECTED_MANIFEST="${EXPECTED_MANIFEST:-ebbc91d414c185bb79df2ef496a89381}"
EXPECTED_FILE_COUNT="${EXPECTED_FILE_COUNT:-52}"
IMAGE="${IMAGE:-golang:1.26-bookworm}"
COUNT="${COUNT:-20}"
SKIP_DOCKER=0
PACKAGES=(./common/singmux/... ./common/mux)

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count) COUNT="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Resolve repository root (script may be invoked from anywhere).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$ROOT"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(ts)" "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# md5 -q is macOS; md5sum is Linux. Prefer the form that works on this host.
file_md5() {
  if command -v md5 >/dev/null 2>&1 && md5 -q /dev/null >/dev/null 2>&1; then
    md5 -q "$1"
  else
    md5sum "$1" | awk '{print $1}'
  fi
}

list_manifest_files() {
  # LC_ALL=C sort matches D66 manifest.sh ordering.
  (find common/singmux -maxdepth 1 -name '*.go'
   find common/singmux/internal/mplsmux -maxdepth 1 -name '*.go') | LC_ALL=C sort
}

file_md5_one() {
  if command -v md5 >/dev/null 2>&1 && md5 -q /dev/null >/dev/null 2>&1; then
    md5 -q "$1"
  else
    md5sum "$1" | awk '{print $1}'
  fi
}

compute_manifest() {
  # D66 form: md5 over lines of "<file-md5>  <path>\n", with exact file count.
  # Prefer the swarm's manifest.sh when present so the constant is shared.
  local swarm_manifest=".bridgespace/swarms/1bd8d8e25967bf/manifest.sh"
  if [[ -x "$swarm_manifest" ]] || [[ -f "$swarm_manifest" ]]; then
    bash "$swarm_manifest" "$EXPECTED_FILE_COUNT" common/singmux common/singmux/internal/mplsmux \
      | head -n1
    return 0
  fi
  local tmp err n digests
  tmp="$(mktemp)"; err="$(mktemp)"
  list_manifest_files >"$tmp"
  n="$(wc -l <"$tmp" | tr -d ' ')"
  if [[ "$n" -ne "$EXPECTED_FILE_COUNT" ]]; then
    rm -f "$tmp" "$err"
    die "manifest file count $n != expected $EXPECTED_FILE_COUNT"
  fi
  digests="$(while IFS= read -r f; do
    printf '%s  %s\n' "$(file_md5_one "$f" 2>>"$err")" "$f"
  done <"$tmp")"
  if [[ -s "$err" ]]; then
    cat "$err" >&2
    rm -f "$tmp" "$err"
    die "md5 failed on one or more manifest files"
  fi
  rm -f "$tmp" "$err"
  if command -v md5 >/dev/null 2>&1 && md5 -q /dev/null >/dev/null 2>&1; then
    printf '%s\n' "$digests" | md5 -q
  else
    printf '%s\n' "$digests" | md5sum | awk '{print $1}'
  fi
}

# ── 0. Bracket ──────────────────────────────────────────────────────────────
log "host: $(uname -s) $(uname -m) | go: $(go env GOVERSION 2>/dev/null || echo missing)"
MANIFEST_BEFORE="$(compute_manifest)"
FILE_COUNT="$(list_manifest_files | wc -l | tr -d ' ')"
log "manifest before: ${MANIFEST_BEFORE} (${FILE_COUNT} files)"
if [[ "$MANIFEST_BEFORE" != "$EXPECTED_MANIFEST" ]]; then
  die "manifest drift: got ${MANIFEST_BEFORE}, want ${EXPECTED_MANIFEST}. Refusing to attribute results to a moving tree (D41/D56)."
fi
log "manifest MATCH ${EXPECTED_MANIFEST}"

# ── 1. GOOS=linux package build (host cross-compile, no source edits) ───────
require_cmd go
HOST_ARCH="$(go env GOHOSTARCH)"
# Prefer the host arch so a local docker linux/arm64 node can re-use artifacts;
# also always prove linux/amd64 (release target) compiles.
for arch in "${HOST_ARCH}" amd64; do
  log "GOOS=linux GOARCH=${arch} CGO_ENABLED=0 go test -c (compile only)"
  out_dir="$(mktemp -d "${TMPDIR:-/tmp}/singmux-linux-build.XXXXXX")"
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go test -c -o "${out_dir}/singmux.test" ./common/singmux
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go test -c -o "${out_dir}/mplsmux.test" ./common/singmux/internal/mplsmux
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go test -c -o "${out_dir}/mux.test" ./common/mux
  for bin in singmux.test mplsmux.test mux.test; do
    [[ -x "${out_dir}/${bin}" ]] || die "missing binary ${out_dir}/${bin}"
    log "  built ${bin} ($(wc -c <"${out_dir}/${bin}" | tr -d ' ') bytes, GOARCH=${arch})"
  done
  rm -rf "${out_dir}"
done
log "GOOS=linux package compile: PASS (arm host arch + amd64)"

if [[ "$SKIP_DOCKER" -eq 1 ]]; then
  log "--skip-docker set; compile-only gate complete"
  MANIFEST_AFTER="$(compute_manifest)"
  [[ "$MANIFEST_AFTER" == "$MANIFEST_BEFORE" ]] || die "tree moved during compile-only run"
  exit 0
fi

# ── 2. Docker Linux soak ────────────────────────────────────────────────────
require_cmd docker
if ! docker info >/dev/null 2>&1; then
  cat >&2 <<EOF
ERROR: docker is installed but the daemon is not reachable.
Operator command on a Linux host (or with a working Docker daemon):

  cd $(pwd)
  EXPECTED_MANIFEST=${EXPECTED_MANIFEST} COUNT=${COUNT} IMAGE=${IMAGE} \\
    ./testing/smuxbench/linux_soak.sh
EOF
  exit 1
fi

log "docker image: ${IMAGE}"
docker pull -q "${IMAGE}" >/dev/null
log "docker pull ok: $(docker run --rm "${IMAGE}" go version)"

REPORT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/singmux-linux-soak.XXXXXX")"
log "report dir: ${REPORT_DIR}"

# Inner script runs *inside* the Linux container. It:
#   - records /proc self RSS samples of the go-test process via a sidecar
#   - runs go test -race -count=N on the singmux packages
#   - captures a final goroutine dump of the test binary via GOTRACEBACK-free
#     end-of-process sampling (Threads from /proc + optional runtime via a
#     tiny probe compiled in-tree without editing owned packages)
INNER="${REPORT_DIR}/inner.sh"
cat >"${INNER}" <<'INNER_EOF'
#!/usr/bin/env bash
set -euo pipefail

COUNT="${COUNT:?}"
PACKAGES="${PACKAGES:?}"
OUT="${OUT:?}"
ROOT="${ROOT:?}"
cd "$ROOT"

mkdir -p "$OUT"
export GOFLAGS="${GOFLAGS:-}"
export GOCACHE="${GOCACHE:-/tmp/gocache}"
export GOMODCACHE="${GOMODCACHE:-/go/pkg/mod}"
mkdir -p "$GOCACHE"

# Tiny probe: report runtime.NumGoroutine after forcing GC. Compiled from a
# temp file outside the repo tree so we never write into owned packages.
PROBE_DIR="$(mktemp -d /tmp/goroutine-probe.XXXXXX)"
cat >"${PROBE_DIR}/main.go" <<'PROBE'
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("probe_goroutines=%d\n", runtime.NumGoroutine())
	fmt.Printf("probe_heap_alloc_bytes=%d\n", ms.HeapAlloc)
	fmt.Printf("probe_sys_bytes=%d\n", ms.Sys)
}
PROBE
go build -o "${OUT}/goroutine_probe" "${PROBE_DIR}/main.go"
rm -rf "${PROBE_DIR}"

sample_proc() {
  # $1 = label, $2 = pid
  local label="$1" pid="$2" rss=0 threads=0
  if [[ -r "/proc/${pid}/status" ]]; then
    rss="$(awk '/^VmRSS:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0)"
    threads="$(awk '/^Threads:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0)"
  fi
  printf '%s pid=%s VmRSS_kB=%s Threads=%s\n' "$label" "$pid" "$rss" "$threads"
}

echo "=== pre-suite probe (idle runtime, not the test binary) ===" | tee "${OUT}/samples.txt"
"${OUT}/goroutine_probe" | tee -a "${OUT}/samples.txt"

echo "=== starting go test -race -count=${COUNT} ${PACKAGES} ===" | tee -a "${OUT}/samples.txt"
# Run tests in background so we can sample /proc for the go-test PID.
# stdout/stderr go to a log; we still want exit code.
set +e
# shellcheck disable=SC2086
go test -race ${PACKAGES} -count="${COUNT}" -timeout 0 >"${OUT}/go-test.log" 2>&1 &
TEST_PID=$!
set -e

echo "go_test_pid=${TEST_PID}" | tee -a "${OUT}/samples.txt"
sample_proc "t+0s" "${TEST_PID}" | tee -a "${OUT}/samples.txt"

# Sample every 15s while the suite runs.
elapsed=0
while kill -0 "${TEST_PID}" 2>/dev/null; do
  sleep 15
  elapsed=$((elapsed + 15))
  sample_proc "t+${elapsed}s" "${TEST_PID}" | tee -a "${OUT}/samples.txt" || true
done

set +e
wait "${TEST_PID}"
TEST_EXIT=$?
set -e
echo "go_test_exit=${TEST_EXIT}" | tee -a "${OUT}/samples.txt"

echo "=== post-suite probe ===" | tee -a "${OUT}/samples.txt"
"${OUT}/goroutine_probe" | tee -a "${OUT}/samples.txt"

# Extract peak RSS / peak Threads from samples of the test process.
# Ignore the post-exit zero sample (pid reaped → VmRSS=0) so delta is meaningful.
awk '
  /VmRSS_kB=/ {
    rss=0; thr=0
    for (i=1;i<=NF;i++) {
      if ($i ~ /^VmRSS_kB=/) { split($i,a,"="); rss=a[2]+0 }
      if ($i ~ /^Threads=/)  { split($i,b,"="); thr=b[2]+0 }
    }
    if (rss > 0) {
      if (!have_first) { firstr=rss; firstt=thr; have_first=1 }
      lastr=rss; lastt=thr
      if (rss > maxr) maxr=rss
      if (thr > maxt) maxt=thr
    }
  }
  END {
    printf "rss_first_kB=%d\nrss_last_nonzero_kB=%d\nrss_peak_kB=%d\nrss_delta_kB=%d\n", firstr+0, lastr+0, maxr+0, (lastr+0)-(firstr+0)
    printf "threads_first=%d\nthreads_last_nonzero=%d\nthreads_peak=%d\nthreads_delta=%d\n", firstt+0, lastt+0, maxt+0, (lastt+0)-(firstt+0)
  }
' "${OUT}/samples.txt" | tee "${OUT}/deltas.txt"

# Surface leak-gate lines (goroutine deltas the tests themselves measure).
grep -E 'SMUX goroutines|leaked|goroutine growth|FAIL|PASS|ok  |--- FAIL' "${OUT}/go-test.log" \
  | tail -n 200 >"${OUT}/goroutine-signals.txt" || true

echo "=== summary ==="
cat "${OUT}/deltas.txt"
echo "go_test_exit=${TEST_EXIT}"
tail -n 30 "${OUT}/go-test.log" || true
exit "${TEST_EXIT}"
INNER_EOF
chmod +x "${INNER}"

log "launching Linux container soak (count=${COUNT}) — this can take a long time under -race"
set +e
docker run --rm \
  -e COUNT="${COUNT}" \
  -e "PACKAGES=${PACKAGES[*]}" \
  -e OUT=/out \
  -e ROOT=/src \
  -v "${ROOT}:/src:ro" \
  -v "${REPORT_DIR}:/out" \
  -v "${INNER}:/inner.sh:ro" \
  -w /src \
  "${IMAGE}" \
  bash /inner.sh
DOCKER_EXIT=$?
set -e

log "docker exit: ${DOCKER_EXIT}"

# ── 3. After-bracket ────────────────────────────────────────────────────────
MANIFEST_AFTER="$(compute_manifest)"
log "manifest after: ${MANIFEST_AFTER}"
if [[ "$MANIFEST_AFTER" != "$MANIFEST_BEFORE" ]]; then
  die "tree moved during soak (before=${MANIFEST_BEFORE} after=${MANIFEST_AFTER}); results are not attributable"
fi
log "manifest before==after MATCH (attributable)"

# ── 4. Emit machine-readable result block for LINUX_SOAK.md paste ───────────
RESULT="${REPORT_DIR}/RESULT.txt"
{
  echo "linux_soak_result"
  echo "timestamp=$(ts)"
  echo "host=$(uname -s)/$(uname -m)"
  echo "image=${IMAGE}"
  echo "go_in_image=$(docker run --rm "${IMAGE}" go version 2>/dev/null | tr -d '\r')"
  echo "count=${COUNT}"
  echo "packages=${PACKAGES[*]}"
  echo "manifest=${MANIFEST_BEFORE}"
  echo "manifest_after=${MANIFEST_AFTER}"
  echo "manifest_stable=yes"
  echo "docker_exit=${DOCKER_EXIT}"
  if [[ -f "${REPORT_DIR}/deltas.txt" ]]; then
    cat "${REPORT_DIR}/deltas.txt"
  else
    echo "deltas=missing"
  fi
  if [[ -f "${REPORT_DIR}/samples.txt" ]]; then
    echo "--- samples ---"
    cat "${REPORT_DIR}/samples.txt"
  fi
  if [[ -f "${REPORT_DIR}/goroutine-signals.txt" ]]; then
    echo "--- goroutine-signals (tail) ---"
    tail -n 80 "${REPORT_DIR}/goroutine-signals.txt"
  fi
  if [[ -f "${REPORT_DIR}/go-test.log" ]]; then
    echo "--- go-test tail ---"
    tail -n 40 "${REPORT_DIR}/go-test.log"
    # Persist full log path for the doc.
    echo "go_test_log=${REPORT_DIR}/go-test.log"
  fi
} | tee "${RESULT}"

log "full result: ${RESULT}"
if [[ "${DOCKER_EXIT}" -ne 0 ]]; then
  log "SOAK FAILED (exit ${DOCKER_EXIT}) — see ${REPORT_DIR}/go-test.log"
  exit "${DOCKER_EXIT}"
fi
log "SOAK PASSED"
exit 0

#!/usr/bin/env bash
set -euo pipefail

mode="${1:-standard}"
case "$mode" in
standard | linux) ;;
*)
	echo "usage: $0 [standard|linux]" >&2
	exit 2
	;;
esac

GOFUMPT_VERSION=v0.11.0
if ! command -v gofumpt >/dev/null 2>&1 || [[ "$(gofumpt -version 2>/dev/null)" != "${GOFUMPT_VERSION} "* ]]; then
	go install "mvdan.cc/gofumpt@${GOFUMPT_VERSION}"
fi
go run ./infra/vformat/main.go -mode check -pwd ./
go vet ./...
go test -timeout 2h ./...
go test -race ./...
go test -gcflags=all=-d=checkptr=2 ./...
go test -tags integration ./common/singmux \
	-run '^(TestSMUXProcessInteropMatrix|TestH2MUXProcessInteropMatrix|TestVLESSTCPProcessMatrix/)' -count=3 -v
go test -tags integration ./testing/scenarios \
	-run '^(TestDirectVersionSkew|TestLegacyMuxVersionSkew|TestXUDPVersionSkew|TestReverseVersionSkew|TestWireGuardVersionSkew)$' -count=1 -v
go test -race ./testing/presence -run '^(TestSevenThousandExactOwnersEndAtZero|TestProductionPresenceOwnershipSourceAudit)$' -count=3
go test -race ./common/mux \
	-run '^(TestXUDPRuntimeThousandRebindsEndAtZero|TestRVSClientWorkerThousandSlotsEndAtZero)$' -count=3
go test -race ./proxy/wireguard -run '^TestWireGuardPresenceThousandHandoffsEndAtZero$' -count=3

if [[ "$mode" != linux ]]; then
	exit 0
fi
if [[ "$(go env GOOS)/$(go env GOARCH)" != "linux/amd64" ]]; then
	echo "linux release gate requires linux/amd64" >&2
	exit 1
fi
: "${XRAY_E2E_YT_INTERFACE:?XRAY_E2E_YT_INTERFACE is required}"
: "${XRAY_E2E_YT_IPV6:?XRAY_E2E_YT_IPV6 is required}"
: "${XRAY_STRUCTURAL_SOAK_SECONDS:?XRAY_STRUCTURAL_SOAK_SECONDS is required}"
: "${XRAY_NATIVE_LINUX_RELEASE:?XRAY_NATIVE_LINUX_RELEASE is required}"
if [[ "$XRAY_NATIVE_LINUX_RELEASE" != 1 ]]; then
	echo "XRAY_NATIVE_LINUX_RELEASE must be 1" >&2
	exit 1
fi
if [[ "$XRAY_E2E_YT_INTERFACE" != yt ]]; then
	echo "XRAY_E2E_YT_INTERFACE must be yt" >&2
	exit 1
fi
if ((XRAY_STRUCTURAL_SOAK_SECONDS < 1800)); then
	echo "XRAY_STRUCTURAL_SOAK_SECONDS must be at least 1800" >&2
	exit 1
fi

XRAY_SMUX_STRESS_CYCLES= XRAY_SMUX_STRESS_TCP_STREAMS= go test -timeout=45m -tags 'integration stress' ./common/singmux \
	-run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
XRAY_SMUX_STRESS_CYCLES=50 XRAY_SMUX_STRESS_TCP_STREAMS=16 go test -timeout=45m -tags 'integration stress' ./common/singmux \
	-run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
go test -timeout=45m -tags 'integration stress performance' ./common/singmux \
	-run '^(TestSMUXServerPerformanceAgainstSingMux|TestCandidatePerformanceAgainstPreviousRelease)$' -count=3 -v
go test -tags 'integration remnanode_release' ./common/singmux \
	-run '^(TestRemnaNodeLinuxReleaseEnvironment|TestRemnaNodeProductionConfigContract|TestRemnaNodeConfigRejectsLiteralNoneFlow|TestRemnaNodeConfigProcessE2E)$' -count=1 -v

deadline=$((SECONDS + XRAY_STRUCTURAL_SOAK_SECONDS))
cycles=0
while ((SECONDS < deadline)); do
	echo "mixed-path soak cycle $((cycles + 1))"
	go test -tags integration ./common/singmux \
		-run '^(TestSMUXProcessInteropMatrix|TestH2MUXProcessInteropMatrix)$' -count=1
	go test -tags integration ./testing/scenarios \
		-run '^(TestDirectVersionSkew|TestLegacyMuxVersionSkew|TestXUDPVersionSkew|TestReverseVersionSkew|TestWireGuardVersionSkew)$' -count=1
	go test -race ./testing/presence -run '^TestSevenThousandExactOwnersEndAtZero$' -count=1
	go test -race ./common/mux -run '^(TestXUDPRuntimeThousandRebindsEndAtZero|TestRVSClientWorkerThousandSlotsEndAtZero)$' -count=1
	go test -race ./proxy/wireguard -run '^TestWireGuardPresenceThousandHandoffsEndAtZero$' -count=1
	cycles=$((cycles + 1))
done
if ((cycles == 0)); then
	echo "structural lifecycle soak executed zero cycles" >&2
	exit 1
fi

artifact="${RUNNER_TEMP:-/tmp}/xray-linux-amd64"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false \
	-ldflags='-s -w -buildid=' -o "$artifact" ./main
"$artifact" version
file "$artifact"
sha256sum "$artifact"
go version -m "$artifact"

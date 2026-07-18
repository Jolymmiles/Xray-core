# Structured logging baseline

Baseline ID: `structured-log-v1-2026-07-19`

This baseline was recorded from dirty revision
`e2ed8329ce2a357186fb521d3f1bf28f3b13d471`. The dirty state contains the
structured logging implementation described by [`DESIGN.md`](DESIGN.md), so
the revision alone is not sufficient to reproduce the numbers.

## Development host

- Go: `go1.26.5`
- Host: Apple M3 Max, Darwin 25.5.0, arm64
- Date: 2026-07-19

Five-sample command:

```sh
go test ./common/log -run '^$' \
  -bench 'Benchmark(JSONEncoderAccess|ConsoleEncoderAccess|RuntimeEmit$|RuntimeEmitParallel|RuntimeEmitSync)' \
  -benchmem -count=5
```

Representative medians:

| Benchmark | Median | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkJSONEncoderAccess` | 217.0 ns/op | 0 | 0 |
| `BenchmarkConsoleEncoderAccess` | 244.9 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmit` | 236.1 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmitParallel` | 186.9 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmitSync` | 144.7 ns/op | 0 | 0 |

`BenchmarkRuntimeEmit` uses the production `drop_new` policy. Once its queue
is saturated, iterations can measure the counted drop path rather than only
accepted-output throughput. It is an allocation and hot-path regression gate,
not a disk-throughput claim.

## Linux runtime development evidence

The logging test binary was cross-compiled for Linux/arm64 and executed in the
locally available native Debian 12 container with networking disabled, a
read-only root filesystem, 1 GiB memory, and 256 PIDs:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go test -c -o /tmp/common-log-linux-arm64.test ./common/log

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m --memory 1g --pids-limit 256 \
  -v /tmp/common-log-linux-arm64.test:/common-log.test:ro debian:12 \
  /common-log.test -test.count=1
```

The full package passed. Five-sample medians from the same container:

| Benchmark | Median | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkJSONEncoderAccess` | 233.8 ns/op | 0 | 0 |
| `BenchmarkConsoleEncoderAccess` | 265.4 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmit` | 188.4 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmitParallel` | 133.0 ns/op | 0 | 0 |
| `BenchmarkRuntimeEmitSync` | 152.7 ns/op | 0 | 0 |

The container exposed two logical CPUs. These Linux/arm64 results prove Linux
runtime behavior and allocation contracts, but they are not Linux/amd64
capacity evidence.

## Linux/amd64 release build

```sh
GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
  go build -o /tmp/xray-logging-linux-amd64 \
  -trimpath -buildvcs=false -gcflags=all=-l=4 \
  -ldflags='-X github.com/xtls/xray-core/core.build=e2ed8329-dirty -s -w -buildid= -checklinkname=0' \
  ./main
```

Result:

- ELF 64-bit LSB x86-64, statically linked and stripped;
- size: approximately 36 MiB;
- SHA-256: `2f41c4b706aefbfa5c4e72d1f2e39ee5cd4677e465e8b47e6bdc9e3510ec483f`;
- embedded Go version: `go1.26.5`.

## Correctness gates

The following completed successfully on the same dirty tree:

```sh
go test ./common/errors ./common/log ./common/session ./app/log \
  ./app/log/command ./app/dispatcher ./infra/conf -count=1

go test -race ./common/errors ./common/log ./common/session ./app/log \
  ./app/log/command ./app/dispatcher ./infra/conf -count=1

go vet ./common/errors ./common/log ./common/session ./app/log \
  ./app/log/command ./app/dispatcher

go test -tags integration ./common/singmux \
  -run '^TestVLESSTCPProcessMatrix/' -count=3 -v

go test -tags integration ./common/singmux \
  -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
```

The VLESS TCP matrix passed 36/36 executions. The SMUX VLESS/Trojan TCP/UDP,
padding on/off matrix passed 40/40 cells. Xray-server SMUX cells additionally
parsed JSON access records and verified that each record contained the real
logical-stream destination rather than `sp.mux.sing-box.arpa:444`.
`TestStructuredRejectedAccessProcess` also started real VLESS and Trojan
servers and verified rejected JSON records including component, inbound,
session ID, source, and reason.

Repository-wide `go test ./... -count=1` was also attempted. Changed logging
packages passed, but the repository was not globally green: the external DoH
test received EOF from `1.1.1.1`, `infra/conf/json` failed and timed out in its
reader tests, and unrelated `testing/scenarios` cases failed. Those failures
are outside this logging change and were not retried or hidden.

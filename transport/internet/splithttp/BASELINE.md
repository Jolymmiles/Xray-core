# XHTTP HTTP/2 flow governor baseline

Baseline ID: `xhttp-h2flow-v1-2026-10-07`

This baseline fixes the cost and the observable behavior of the HTTP/2 flow
governor (`h2flow*.go`) for XHTTP over HTTP/2 on TCP. The governor is off
unless `XRAY_XHTTP_FLOW=on` or `xhttpSettings.extra.h2Flow.enabled` turns it
on; with it off, the code below is never in the data path.

## Source and conditions

- Xray commit: `a6321d10c66f688812075dbb91267ee01e2f91fd` (PR #17 re-review
  fixes on `bdbac60e`).
- Host: linux/amd64 container, AMD Ryzen 5 5600 (12 threads), Go 1.27.1,
  build tag `http2legacy` as CI and releases build.
- Benchmark command:

  ```sh
  go test -tags http2legacy ./transport/internet/splithttp \
    -run '^$' -bench 'BenchmarkFlow' -benchtime=2s -count=3
  ```

## Microbenchmarks

One MiB of DATA in default-size frames on one stream, plus the credit for it,
read in 16 KiB buffers (`BenchmarkFlowRead`, client to server) or written in
16 KiB writes (`BenchmarkFlowWrite`, server to client). "Stock" is the bare
connection; the replay connection copies or discards, so stock is the cost of
the copy alone. Medians of three runs:

| Benchmark | Stock | Governed | Allocations governed |
| --- | --- | --- | --- |
| Read, per MiB | 19.6 µs | 58.7 µs (17.9 GB/s) | 65, 1.6 KB |
| Write, per MiB | 0.16 µs | 192.5 µs (5.4 GB/s) | 65, 1.6 KB |

The governor parses every frame header and rewrites credit, so its cost is
per frame (64 per MiB), not per byte. All allocations are the slice headers
`bytespool.Free` boxes into its `sync.Pool`, one per read or write. One core
governs well over the line rate of any link the governor is meant for.

## Process gates

```sh
MIHOMO_E2E_BIN=/path/to/mihomo SING_BOX_E2E_BIN=/bin/true \
  go test -tags 'integration http2legacy' ./common/singmux \
    -run 'TestXHTTPFlowProcess|TestXHTTPMuxCoolProcess' -timeout 30m
```

- `TestXHTTPFlowProcess` (Mihomo Meta 1.10.0 from module v1.19.32): eight
  concurrent 1 MiB echoes and 16 MiB down and up on one session, byte for
  byte, from Xray and Mihomo clients in stream-up and packet-up, governor on
  and off: all 8 transfer cases pass. `governor=true/settings` fails: the
  governed TLS listener sends its SETTINGS only after the client preface
  (open item, see `h2flow_verify_listener_test.go`).
- `TestXHTTPMuxCoolProcess`: 6/6 pass.

## Behavior gates

Unit tests fix what a peer can observe and what the governor may hold:

- control frames: malformed SETTINGS and PING, SETTINGS above 16 KiB, and any
  frame inside a HEADERS or PUSH_PROMISE header block pass byte for byte and
  get the stock errors (`h2flow_verify_settings_test.go`,
  `h2flow_verify_control_test.go`);
- a failed write of rewritten frames closes the connection; nothing follows a
  torn frame (`h2flow_verify_inject_test.go`);
- a new `SETTINGS_INITIAL_WINDOW_SIZE` moves open streams: a raise credits
  them after the SETTINGS frame, a lowering never leaves the sender more than
  the real window, and the connection is given up when no value can express
  it (`TestFlowInitialWindow*`, `TestFlowModelWindowChanges`);
- memory: 32 upload streams nobody reads hold 1 MiB on the connection, as
  stock (`TestFlowServerUnreadPerConnection`); stream churn against a client
  that stopped reading keeps the credit queue at a few frames and live heap
  level with stock (`TestFlowInjectedQueueBounded`,
  `TestFlowInjectedQueueHeapVsStock`).

## Network measurements

Linux stand from the PR description: two network namespaces joined by a veth
pair, netem delay and rate with a queue sized to the bandwidth-delay product,
server governed, client official Xray; medians of five rounds. Measured on
`bdbac60e`, before the re-review fixes. Those leave the download path as it
was but hold the upload connection window at Go's 1 MiB until a reader takes
data, so the upload rows are to be measured again on this commit.

| Scenario | Stock | Governed |
| --- | --- | --- |
| Download 100 Mbit/s, RTT 50 ms: PING beside it p50 / p95 | 789 / 1711 ms | 65 / 233 ms |
| Download through link dips: recovery after the second dip | 6.9 s | 0.7 s |
| Slow reader: client memory | 118 MB | 38 MB |
| One upload, 100 Mbit/s, RTT 150 ms: rate / PING | 6.7 MB/s / 153 ms | 10.9 MB/s / 190 ms |
| 20 uploads into a slow server: PING p95 | 8.0 s | 0.48 s |

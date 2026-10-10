# XHTTP HTTP/2 flow governor baseline

Baseline ID: `xhttp-h2flow-v1-2026-10-07`

This baseline fixes the cost and the observable behavior of the HTTP/2 flow
governor (`h2flow*.go`) for XHTTP over HTTP/2 on TCP. The governor is off
unless `XRAY_XHTTP_FLOW=on` or `xhttpSettings.extra.h2Flow.enabled` turns it
on; with it off, the code below is never in the data path.

## Source and conditions

- Revisions, all clean trees: benchmarks and the network rows on `bfe16614`
  (re-review fixes on `bdbac60e`), gates re-run on `28392012`; the next
  commit (server shows Go's 1 MiB initial window) changes only the upload
  start and was re-measured on the upload rows, with the same results.
- Not re-measured since: `4703622c` and `4937e234` (the upload connection
  window counts unread data from the connection's own counters and leaves
  finished uploads out), `6807a2e6` (TLS stays visible to net/http) and
  `7d61adc0` (first PING after the client preface). The upload rows below
  may differ on the current tree; the slow-server scenario was measured
  again, see "Slow readers and the shared connection room". Unit, race and
  process gates were re-run on `7d61adc0`.
- Host: linux/amd64 container, AMD Ryzen 5 5600 (12 threads), Go 1.27.1,
  build tag `http2legacy` as CI and releases build.
- Benchmark command:

  ```sh
  go test -tags http2legacy ./transport/internet/splithttp \
    -run '^$' -bench 'BenchmarkFlow' -benchtime=2s -count=5
  ```

## Microbenchmarks

One MiB of DATA in default-size frames on one stream, plus the credit for it,
read in 16 KiB buffers (`BenchmarkFlowRead`, client to server) or written in
16 KiB writes (`BenchmarkFlowWrite`, server to client). "Stock" is the bare
connection; the replay connection copies or discards, so stock is the cost of
the copy alone. Medians of five runs:

| Benchmark | Stock | Governed | Allocations governed |
| --- | --- | --- | --- |
| Read, per MiB | 20.1 µs | 59.8 µs (17.5 GB/s) | 65, 1.6 KB |
| Write, per MiB | 0.17 µs | 203.0 µs (5.2 GB/s) | 65, 1.6 KB |

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

- `TestXHTTPFlowProcess` (Mihomo Meta 1.10.0): eight concurrent 1 MiB
  echoes and 16 MiB down and up on one session, byte for byte, from Xray and
  Mihomo clients in stream-up and packet-up, governor on and off, plus the
  SETTINGS each server advertises: all 10 cases pass on `7d61adc0`.
- `TestXHTTPMuxCoolProcess`: 6/6 pass on `7d61adc0`.

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
  that stopped reading keeps the credit queue at a few frames
  (`TestFlowInjectedQueueBounded`); bodies a handler has read do not hold
  the connection window while their responses wait
  (`TestFlowReadBodiesReleaseConnectionWindow`);
- TLS probes: plaintext HTTP to the TLS port gets stock's 400, ALPN
  `http/1.1` is served as HTTP/1.1, the server sends its SETTINGS before the
  client preface and nothing else until it arrives, and it closes like stock
  after a 431 (`h2flow_verify_listener_test.go`).

## Network measurements

Linux stand: two network namespaces joined by a veth pair, netem delay and
rate with a queue sized to the bandwidth-delay product, TCP buffers up to
32 MB, server `bfe16614` (upload rows `5a8dcf03`), client official Xray
v26.9.30. Medians of five
rounds; the governor column of the slow-server row is from an eight-round
run, the last row from a twelve-round run of both.
"Stock" is the governor off.

| Scenario | Stock | Governed |
| --- | --- | --- |
| Download 100 Mbit/s, RTT 50 ms: PING beside it p50 / p95 | 1021 / 2424 ms | 66 / 216 ms |
| Download beside short requests: PING p50 / p95 | 453 / 875 ms | 65 / 212 ms |
| One upload, 100 Mbit/s, RTT 300 ms | 3.2 MB/s | 9.5 MB/s |
| One upload, 50 Mbit/s, RTT 150 ms | 5.7 MB/s | 5.7 MB/s |
| Uploads into a slow server: PING p50 / p95 | 218 / 7150 ms | 53 / 511 ms |
| First 3 MB of a new stream, RTT 150 ms ± 20 ms | 4.1 s | 4.2 s |

The last row is bimodal for every build, stock included: runs land near
2.9 s or 4.1–5.1 s (7 of 12 slow for stock, 6 of 12 governed), which is TCP
on the jittered link rather than the window.
Integrity: byte-exact pattern transfers up and down, direct, behind a TCP
proxy and with jitter, 65 transfers and 125 MB, no bad bytes, short reads or
errors.

### Slow readers and the shared connection room

Measured for the change that allows a reading stream what it already holds
(`upConnRelease`). The stand is `testing/xhttpflow/slowreader`: `stand.py`
sets up the namespaces and the link, writes the configs, drives the uploads
and the small requests and prints the table; `origin` is the far end. It
creates namespaces of its own and removes them, its temporary directory and
its processes when it ends.

```sh
go build -o origin ./testing/xhttpflow/slowreader/origin
sudo python3 testing/xhttpflow/slowreader/stand.py     --origin ./origin --client /path/to/xray-v26.9.30     --server before=/path/to/xray-14d049d0 --server after=/path/to/xray-c13ea885     --runs 36
```

- Revisions, clean trees: before `14d049d0`, after `c13ea885`, each built
  with Go 1.27.2 and `-tags http2legacy`; same host as above, in a privileged
  container. Client: official Xray v26.9.30, XHTTP over REALITY in its
  default mode, `xmux.maxConnections` 3. REALITY keys are made per run of
  the stand.
- Two network namespaces joined by a veth pair, netem on both ends: 100 Mbit/s,
  25 ms each way, a queue of twice the bandwidth-delay product; TCP buffers
  up to 32 MB. Twenty uploads run for 12 s into an origin that reads
  100 KB/s from each. Beside them a small request (`GET /ping` through the
  tunnel, a new session each time, answered `200` with `pong`) is sent 0.3 s
  after the previous one ends, on the same three connections: about thirty
  per run, fewer when they stall.
- 36 runs per build, all runs shuffled together. Per run: p50 and p95 of the
  request times, and the server's peak RSS sampled every 0.25 s. A request
  that fails or takes over 10 s counts as 10 s, and the request in flight
  when the uploads end is waited for and counted. A run is valid only if
  all twenty uploads were still sending at the deadline; a single invalid
  run makes the stand exit with status 1, after the table. The table gives
  the median over runs and the worst run.

| | Before | After |
| --- | --- | --- |
| Valid runs | 36 of 36 | 36 of 36 |
| Requests failed or over 10 s | 0 of 932 | 0 of 1042 |
| Runs with ping p95 above 2 s | 7 | 0 |
| Worst ping p95 | 7.94 s | 0.89 s |
| Median ping p50 / p95 | 53 / 521 ms | 53 / 529 ms |
| Median server peak RSS | 40.2 MB | 39.8 MB |

Two earlier pairs of 36 runs on the same revisions undercount the stalls and
are kept only for the record: both dropped the request still in flight when
a run ended, and failed requests. With the larger driver this stand was cut
from: 3 runs above 2 s (4.4 / 5.8 / 7.2 s) against 0, worst p95 7.2 s
against 0.88 s. With the first version of this stand (`39ffc35d`): 1 run
(6.5 s) against 0, worst p95 6.51 s against 0.74 s.

Limits:

- The uploads themselves pause for 4 to 5 s about every 10 s in this
  scenario, governor on or off. That is not flow control: the kernel grows
  the server's send buffers towards the slow origin to about 2.4 MB each and
  wakes the blocked writer only after a large part has drained. The change
  does not touch it; it only keeps other requests moving meanwhile.
- A stream can still spend stream credit granted before its cap shrank, and
  the allowance follows what it then holds; the total stays within the
  connection window the server really grants (6 MiB by default).
- One link, one client implementation, no loss or jitter; peak RSS is the
  whole process, not the governor alone.

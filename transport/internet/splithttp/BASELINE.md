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
- Both were run again on `a79b4aac`, the server with its default send
  window, against Mihomo Meta v1.19.32 (release binary, linux/amd64): 10 of
  10 and 6 of 6 pass.

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
its processes when it ends, and fails if a namespace cannot be removed. A
measurement still running after 98 s per run is taken as stuck: the stand
stops it, tears down and exits with status 1. When the stand fails, it
prints what `origin` wrote to stderr.

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

### Credit quanta and the connection send window

Measured for two changes: credit is handed on in quanta of 16 to 32 KiB
(`hold`), and the streams of one server connection share
`h2Flow.maxConnectionSendWindow` (`downRelease`), 4 MiB unless set.

The stand is `testing/xhttpflow/slowreader/stand.py` with
`--workload downloads` or `--workload uploads`; see its head for what a run
is and when it counts.

```sh
go build -o origin ./testing/xhttpflow/slowreader/origin
S="sudo python3 testing/xhttpflow/slowreader/stand.py --origin ./origin --client /path/to/xray-v26.10.10"
NOLIMIT='nolimit={"enabled": true, "maxConnectionSendWindow": -1}'
# twenty slow readers
$S --workload downloads --mbit 1000 --readers 20 --read-rate 100000 --client-limit-mb 40 \
   --server stock=xray-da42e75f --h2flow 'stock={"enabled": false}' --server before=xray-da42e75f \
   --server after=xray-323ca8b1 --server nolimit=xray-323ca8b1 --h2flow "$NOLIMIT" --runs 5
# eight downloads, for --rtt 50, 150, 300; one download with --readers 1
$S --workload downloads --mbit 1000 --rtt 150 --readers 8 --read-rate 0 \
   --server before=xray-da42e75f --server after=xray-323ca8b1 \
   --server nolimit=xray-323ca8b1 --h2flow "$NOLIMIT" --runs 5
# four uploads; one with --readers 1
$S --workload uploads --mbit 1000 --readers 4 --read-rate 0 \
   --server before=xray-da42e75f --server after=xray-323ca8b1 --runs 5
```

- Revisions: before `da42e75f` (clean tree), after `323ca8b1` (its tree,
  built before the commit was made), each with Go 1.27.2 and
  `-tags http2legacy`. The stock and "no limit" columns and the upload rows
  are from `439f0110`, which differs only in `clientHolds`: a function those
  paths do not reach. Client: official Xray v26.10.10, XHTTP over REALITY,
  `xmux.maxConnections` 3. Host: linux/amd64 privileged container under
  Docker Desktop (WSL2 kernel), AMD Ryzen 5 5600; the host was otherwise
  idle but is a desktop.
- 12 s per run, five runs per build, all shuffled together, medians. The
  link is netem at 1 Gbit/s and RTT 50 ms unless stated; the stand tops out
  near 114 MB/s.
- Client memory is `RssAnon` of the client process sampled every 50 ms.
  With `--client-limit-mb 40` a client above 40 MiB is killed at once: a
  model of a process memory limit such as the one on a phone's network
  extension.
- CPU is the processor time of the Xray process, user and system, per
  gigabyte moved. It includes the kernel's work on the emulated link, so
  only the columns compare.

Twenty downloads each read at 100 KB/s. "Stock" is the governor off, "no
limit" is `maxConnectionSendWindow: -1`:

| | Stock | Before | After | After, no limit |
| --- | --- | --- | --- | --- |
| Client peak RssAnon, median / worst | 43.8 / 44.6 MB | 42.7 / 43.4 MB | 24.1 / 24.6 MB | 42.5 / 43.9 MB |
| Client killed at 40 MiB | 5 of 5 | 5 of 5 | 0 of 5 | 5 of 5 |
| Median ping p50 / p95 | 10 / 10 s | 10 / 10 s | 52 / 214 ms | 10 / 10 s |

The client dies about 1.1 s after the start: it is the opening burst of
twenty streams, not growth. At 100 Mbit/s the same scenario holds 12.7 MB
before and 12.6 MB after, worst 13.9 MB both.

The same scenario against other clients, three runs each, and eight
downloads at RTT 150 ms, two runs each (the table is `323ca8b1`; on
`60e39569` all seven peak at 22.9 to 23.9 MB at 4 MiB and 16.7 to 17.6 MB
at 2 MiB, none killed, and read 71.6 to 72.3 MB/s, with one run of 47.4 on
v26.7.28): the limit must hold for every client
and must not slow one whose connection credit comes otherwise. Without the
limit every one of these clients was killed, 3 of 3 (`439f0110`).

| Client | Slow readers: median / worst, killed | 8 downloads, RTT 150 ms |
| --- | --- | --- |
| Xray v26.10.10, release | 23.6 / 23.9 MB, 0 of 3 | 72.0 MB/s |
| Xray v26.9.30, release | 23.3 / 23.5 MB, 0 of 3 | 71.9 MB/s |
| Xray v26.7.28, release | 23.5 / 23.8 MB, 0 of 3 | 71.1 MB/s |
| Xray v26.5.9, release | 23.3 / 24.2 MB, 0 of 3 | 48.4 and 71.4 MB/s |
| v26.10.10 built with `-tags http2legacy` | 23.6 / 23.6 MB, 0 of 3 | 70.9 MB/s |
| v26.10.10 with `golang.org/x/net` v0.61.0 | 23.4 / 23.5 MB, 0 of 3 | 70.8 MB/s |
| v26.10.10 with both | 23.0 / 23.5 MB, 0 of 3 | 70.5 MB/s |

v26.5.9 reads 48 MB/s in about one run of six whichever way the limit is
counted: 1 of 6 on `439f0110`, 1 of 6 on `323ca8b1`, the rest 70 to 72.

What the limit costs is the sum of many downloads on one connection on a
long path, at most the limit per round trip. MB/s read, three connections:

| | Before | After | After, no limit |
| --- | --- | --- | --- |
| 8 downloads, RTT 50 ms | 114.1 | 113.9 | 114.1 |
| 8 downloads, RTT 150 ms | 103.3 | 71.3 | 102.7 |
| 8 downloads, RTT 300 ms | 72.2 | 30.9 | 74.1 |
| One download, RTT 50 ms | 71.3 | 72.4 | |
| One download, RTT 300 ms | 10.3 | 9.9 | |

The last row is from `439f0110`.

CPU seconds per gigabyte, server / client:

| | Before | After |
| --- | --- | --- |
| 4 uploads, 115 MB/s | 25.7 / 17.3 | 23.1 / 15.0 |
| One upload, 91 MB/s | 24.5 / 17.1 | 22.1 / 14.9 |
| 8 downloads | 23.3 / 20.9 | 23.6 / 21.9 |
| One download | 22.2 / 17.2 | 21.6 / 17.3 |

At 100 Mbit/s, RTT 50 ms, the request beside the load does not change: p50 /
p95 65 / 226 against 66 / 251 ms beside 8 downloads, 52 / 367 against
52 / 352 ms beside twenty slow readers, 52 / 398 against 52 / 374 ms beside
twenty uploads into a slow origin.

One frame from the client on a server connection with streams open past the
limit (`BenchmarkFlowClientFrame`, `-benchtime=2000x`, medians of three).
With the total found by walking the streams (`154e636c`) a SETTINGS frame
cost 35 µs with 100 streams and 5.2 ms with 1000; the table is `439f0110`:

| Frame | Streams | No limit | Limit |
| --- | --- | --- | --- |
| SETTINGS | 100 | 2.2 µs | 2.4 µs |
| SETTINGS | 1000 | 29.4 µs | 30.7 µs |
| WINDOW_UPDATE | 1000 | 2.5 µs | 2.5 µs |

`BenchmarkFlowRead` and `BenchmarkFlowWrite` do not show the quanta: the
replay connection has no system calls and no peer that answers credit.
`TestFlowCreditWaitsForAQuantum` fixes the local effect instead: 128 KiB of
credit in 4 WINDOW_UPDATE frames where there were 32.

What an observer sees of these changes, against the governor before them;
stock Go differs from both as the rest of this file says:

- Handshake, SETTINGS values, the PING schedule, preface handling and the
  replies to malformed or unauthenticated input are not touched; the
  probe-comparison tests pass unchanged.
- Passive, on the path, TLS records only. A governed server during uploads,
  and a governed client during downloads, sends fewer credit records: one
  per 16 to 32 KiB the reader took instead of one per 4 KiB or so. A
  governed server with more than sixteen downloads starting on one
  connection sends less in the first round trip, and with many downloads on
  a long path less per round trip from then on.
- A TLS terminator in front of the server reads the frames: it sees
  WINDOW_UPDATE increments of 16 to 32 KiB from either governed end where
  they were about 4 KiB, and a server that leaves stream window unused.
- An active prober that cannot authenticate opens no download and sees
  none of it.
- Not measured: record sizes and timing were not captured and compared, and
  nothing was run against a classifier. The record counts above follow from
  the frame counts in the unit test, not from a capture.

Limits:

- What the client holds is counted by stream and by connection, and the
  larger taken (`clientHolds`). The connection's count is what covers a
  download the server has ended and the client has not read
  (`TestFlowSendWindowCountsFinishedDownloads`). It is used only once the
  client has returned connection credit in small steps; until then, and for
  a client that never does, ended downloads are outside the limit
  (`TestFlowSendWindowWithoutConnectionCredit`).
- On the stand an Xray client does not keep short ended downloads in its
  own memory, governor on or off (192 downloads of 256 KiB read at 1 KB/s
  each: 13 to 17 MB): it writes them on to the application's socket, into
  the kernel. `--app-buffer 32768` bounds that, as where the reader lives
  in the client's process. Then, with `--readers 192 --stagger 0.055
  --read-rate 1000 --download-bytes 262144 --client-limit-mb 40`, three
  runs each: stock is killed 3 of 3; `323ca8b1` peaks at 38.7 MB (worst
  38.9), `5ae2b3de` at 34.9 MB (worst 35.5), neither killed.
- A first version counted every connection WINDOW_UPDATE as credit returned
  and failed on the stand, client killed at 40 to 44 MB: a Go client opens
  with one of 1 GiB to raise its window. The harness now has that frame
  (`goClientStart`).
- The limit is per connection and the server does not know how many
  connections a client keeps: the client holds about the limit times its
  connections above its base of about 11 MB.
- The limit is what is configured, whatever window the client announces
  (`60e39569`; before, it was never below that window, so nothing under the
  4 MiB a Go client announces took effect). A governed bridge is held to it
  like any other client; `-1` on its inbound lifts that. One download is
  held to the limit per round trip as well. `60e39569`, three runs each,
  `--h2flow` with `maxConnectionSendWindow` 2097152 and 1048576:

  | | 4 MiB | 2 MiB | 1 MiB |
  | --- | --- | --- | --- |
  | Twenty slow readers, client peak | 23.0 MB | 17.3 MB | 14.4 MB |
  | 192 slow downloads of 4 MB, client peak, killed | 40.1 MB, 3 of 3 | 35.0 MB, 0 of 3 | 32.6 MB, 0 of 3 |
  | 192 ended downloads nobody reads, client peak | 35.6 MB | 31.2 MB | 28.5 MB |
  | One download, RTT 50 ms | 64.9 MB/s | 38.9 MB/s | 19.6 MB/s |
  | One download, RTT 150 ms | 24.1 MB/s | 12.1 MB/s | 6.1 MB/s |
  | 8 downloads, RTT 150 ms | 72.3 MB/s | 36.7 MB/s | 18.6 MB/s |

  At the default, one download at RTT 50 ms reads the same on `da42e75f`,
  `5ae2b3de` and `60e39569`: 67.9, 68.2 and 68.8 MB/s, six shuffled runs.
- A stream past the limit keeps what the server's stack was shown at the
  start, 16 KiB since `5ae2b3de` (`flowShownLimited`; 65535 before): forty
  streams opened at once may be sent 4.4 MiB, not 4
  (`TestFlowSendWindowBoundsManyStreams`). A client that does not announce
  an initial window keeps 65535 per stream: the value is lowered by
  rewriting the one it sends.
- The limit is per connection, so with three connections and hundreds of
  streams the client is still near 40 MiB: 192 slow downloads of 4 MB
  started over ten seconds kill it 3 of 3 on stock, on `323ca8b1` and on
  `5ae2b3de`. Its process holds about 30 MB above its idle 12.4 MB where
  the windows account for 15. That is not the garbage collector's headroom:
  with the client limit at 60 MiB the client peaks at 43.0 MB, at 38.6 with
  `GOGC=50` and at 36.8 with `GOGC=25`, and with twenty streams `GOGC`
  changes nothing (23.6, 23.6, 23.2 MB). Nor a client buffer of its own
  (`policy.bufferSize` 0 changes nothing), nor the sessions as such (192
  open with 1000-byte bodies take 12.4 MB). Every figure here fits about
  1.2 times the limit on each connection and 80 KB for each stream data
  moves on, above the idle client; where those 80 KB are was not found.
- `5ae2b3de` against `323ca8b1`: twenty slow readers 23.7 against 23.5 MB
  and eight downloads at RTT 150 ms 72.1 against 71.6 MB/s (three runs);
  at 100 Mbit/s the request beside eight downloads p50 / p95 66 / 310
  against 66 / 268 ms (ten runs, p95 of single runs 157 to 449 against 161
  to 327), beside twenty slow readers 52 / 314 against 52 / 334 ms (four
  runs).
- A client that has returned nothing in small steps when the guard fires has
  the limit lifted for that connection (`TestFlowGuardLiftsSendWindow`), or a
  client that credits at half its window would stop for good. A Go client
  whose every reader is stopped from the first byte is such a connection too.
- The client is Xray for linux/amd64, not a phone; kernel socket buffers
  are not counted, and a spike shorter than 50 ms can be missed.
- CPU differences on downloads are inside the noise of five runs; the
  upload rows repeat across runs.
- `TestFlowChainedGovernorsSlowReaders` stopped once in a full `-race` run
  of `154e636c` in review. It has not come back: 150 `-race` runs of it
  alone, with and without the send window, on a tree that differs from
  `323ca8b1` only in how the send window is totalled, 40 more and a full
  `-race` run of the package on `323ca8b1` pass. The cause of that one stop is not
  known; the test now logs its seed and both ends' counters if it happens
  again.

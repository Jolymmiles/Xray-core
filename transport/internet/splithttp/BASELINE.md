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
- Both were run again on `e9737656`, the server with its default send
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

Measured for two changes: credit was handed on in quanta of 16 to 32 KiB
(`hold`), and the streams of one server connection share
`h2Flow.maxConnectionSendWindow` (`downRelease`), 4 MiB unless set. The
quanta have been withdrawn; "Limits" below says why and what they were
measured to give. Of the figures here, the CPU of the upload rows went with
them.

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

The same scenario against other clients, and eight downloads at RTT 150 ms,
server `a21c075d`, five runs each: the limit must hold for every client and
must not slow one whose connection credit comes otherwise. Without the limit
every one of these clients was killed, 3 of 3 (`439f0110`).

| Client | Slow readers, 4 MiB: median / worst, killed | The same, 2 MiB | 8 downloads, RTT 150 ms: median (range) |
| --- | --- | --- | --- |
| Xray v26.10.10, release | 23.7 / 24.1 MB, 0 of 5 | 17.4 / 17.6 MB, 0 of 5 | 72.3 (71.0 to 72.5) MB/s |
| Xray v26.9.30, release | 23.9 / 24.2 MB, 0 of 5 | 17.6 / 17.9 MB, 0 of 5 | 72.3 (71.4 to 72.4) MB/s |
| Xray v26.7.28, release | 23.5 / 23.9 MB, 0 of 5 | 16.9 / 17.1 MB, 0 of 5 | 71.8 (71.3 to 72.5) MB/s |
| Xray v26.5.9, release | 23.1 / 23.1 MB, 0 of 5 | 16.6 / 17.1 MB, 0 of 5 | 72.3 (71.4 to 72.4) MB/s |
| v26.10.10 built with `-tags http2legacy` | 23.2 / 23.4 MB, 0 of 5 | 17.0 / 17.3 MB, 0 of 5 | 72.4 (71.5 to 72.7) MB/s |
| v26.10.10 with `golang.org/x/net` v0.61.0 | 23.4 / 24.1 MB, 0 of 5 | 17.1 / 17.4 MB, 0 of 5 | 67.6 (47.4 to 72.5) MB/s |
| v26.10.10 with both | 23.2 / 24.1 MB, 0 of 5 | 17.0 / 17.2 MB, 0 of 5 | 71.5 (48.8 to 72.0) MB/s |

A run of 47 to 49 MB/s turns up now and then on any of these clients and on
any way of counting the limit. It is the client's choice of connection, not
the governor: an Xray client picks one of its connections at random for each
new session (`GetXmuxClient`), so eight downloads land on only two of three
connections in 11.7% of runs, and the limit is per connection. Of 130 runs
of this scenario at 4 MiB, 13 read 48 MB/s, two thirds of the others' 72.
With the client held to one, two and three connections the eight downloads
read 24.7, 48.4 and 72.3 MB/s (four runs each, `f84a597c`).

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
limit (`BenchmarkFlowClientFrame`, `-benchtime=2000x -count=5`, medians, on
`a21c075d`). With the total found by walking the streams (`154e636c`) a
SETTINGS frame cost 35 µs with 100 streams and 5.2 ms with 1000:

| Frame | Streams | No limit | Limit |
| --- | --- | --- | --- |
| SETTINGS | 100 | 2.26 µs | 2.33 µs |
| SETTINGS | 1000 | 31.1 µs | 31.1 µs |
| WINDOW_UPDATE | 100 | 2.56 µs | 2.56 µs |
| WINDOW_UPDATE | 1000 | 2.56 µs | 2.55 µs |

`BenchmarkFlowRead` and `BenchmarkFlowWrite` did not show the quanta: the
replay connection has no system calls and no peer that answers credit.

What an observer sees of these changes, against the governor before them;
stock Go differs from both as the rest of this file says:

- Handshake, SETTINGS values, the PING schedule, preface handling and the
  replies to malformed input are not touched; the probe-comparison tests
  pass unchanged.
- One reply to legal input differs from stock, as it did before these
  changes: a client that lowers its initial window under the credit the
  server's stack was forwarded and has not used. Stock applies it; the
  governor cannot pass it on and gives the connection up. A new stream is
  forwarded 196609 bytes before any data, so a client that opens a GET and
  lowers its window under that is closed where stock answers, and it needs
  no credentials for that. The threshold is what the stream was forwarded
  less what the client returned, so it grows as a download runs and its cap
  with it, up to the client's window less 65535: measured on `main`
  (`9ce136ea`) with 4 MiB announced, 2097152 after 1 MiB read and 4128769
  after 8 MiB, where any lowering by more than 64 KiB closes. With a send window `5ae2b3de` to `ce4624fc`
  forwarded 245760 and closed in that wider range; `09136349` forwards
  196609 again (`TestFlowInitialWindowDecrease`, with the send window off
  and at its default), and `0a5f8c08` keeps it so after a SETTINGS frame that
  carries no initial window (`TestFlowSendWindowSettingsWithoutWindow`).
- Passive, on the path, TLS records only. A governed server with more than
  sixteen downloads starting on one connection sends less in the first
  round trip, and with many downloads on a long path less per round trip
  from then on. Credit is released as it was before the quanta.
  A capture made in the review of the withdrawal, in a user and network
  namespace with `lo` at MTU 1500, VLESS + XHTTP + REALITY in stream-one,
  30 MB at 12.5 MB/s, five shuffled runs, medians:

  | Credit | h2Flow off | `da42e75f` | `391e5f06` | `e17be671` |
  | --- | --- | --- | --- | --- |
  | Upload, server to client: TLS records | 3591 | 3271 | 1061 | 2831 |
  | Upload: WINDOW_UPDATE frames | 7324 | 7219 | 1808 | 7230 |
  | Download, governed client to server: records | 3663 to 3665 | 3663 to 3665 | 3663 to 3665 | 3663 to 3665 |

  Almost every credit segment carried one record: all but under 0.1%,
  where a few, more of them on the download side, start 2 to 17 records.
  A record that carries only WINDOW_UPDATE frames is 30 + 13k bytes for
  k + 1 of them; some carry a PING or the like beside. On uploads the
  quanta cut the records to about a third; without them there is about
  one per 10 KiB, 2831 on `e17be671` against 3271 on `da42e75f`. On a
  governed client's downloads the quanta never changed the count: the
  connection's update went out with every read and only the stream's
  waited, so about three quarters of the records were 30-byte single
  updates where stock Go, `da42e75f` and `e17be671` send 43-byte pairs.
  The capture has a round trip of microseconds and segment offload.
- A TLS terminator in front of the server reads the frames: it sees a
  server that leaves stream window unused.
- An active prober that cannot authenticate gets no data on a stream, so
  it sees none of the limit; what it can do is the lowering above.
- Not measured: record timing, and anything on a real path. Nothing was run
  against a classifier.

Limits:

- What the client holds is counted by stream and by connection, and the
  larger taken (`clientHolds`). The connection's count is what covers a
  download the server has ended and the client has not read
  (`TestFlowSendWindowCountsFinishedDownloads`). It is used only once the
  client has returned connection credit in small steps; until then, and for
  a client that never does, ended downloads are outside the limit
  (`TestFlowSendWindowWithoutConnectionCredit`).
- A connection WINDOW_UPDATE that takes the window above where it has been
  is taken for a raise, and what the client had not returned by then drops
  out of the connection's count (`TestFlowSendWindowRaiseDropsUnread`). A
  raise cannot be told from a large return in such a credit; counting it as
  a return would hold a client for data it does not have, so the count errs
  towards sending. Xray and Mihomo clients raise the window once, at the
  start.
- A first version counted every connection WINDOW_UPDATE as credit returned
  and failed on the stand, client killed at 40 to 44 MB: a Go client opens
  with one of 1 GiB to raise its window. The harness now has that frame
  (`goClientStart`).
- A client with a governor of its own is not held to the limit. It
  announces the protocol default, and a client that announces no more than
  that is shown all of it (`shownDown`): the server governor then hands on
  all such a client returns, and the client governor opens each stream with
  credit of its cap above what it showed. Forty downloads nobody reads hold
  10 MiB at a governed client with the limit as without
  (`TestFlowChainedClientNotHeldToSendWindow`); what it holds is up to its
  own governor. Showing such a client less stopped downloads for good
  (`TestFlowChainedStallAtSendWindow`, `5ae2b3de` to `a21c075d`): the
  server governor kept back 49151 bytes the client governor counted on.
- The limit is per connection and the server does not know how many
  connections a client keeps.
- The limit is what is configured, whatever window the client announces
  (`60e39569`; before, it was never below that window, so nothing under the
  4 MiB a Go client announces took effect). One download is held to the
  limit per round trip as well. `a21c075d`, five runs each, `--h2flow` with
  `maxConnectionSendWindow` 2097152 and 1048576; "192 slow downloads" is
  `--readers 192 --stagger 0.055 --read-rate 1000 --download-bytes
  4000000`, the completed ones the same with `--download-bytes 262144
  --app-buffer 32768`:

  | | 4 MiB | 2 MiB | 1 MiB |
  | --- | --- | --- | --- |
  | Twenty slow readers: client peak, median / worst | 23.7 / 24.1 MB | 17.3 / 17.6 MB | 14.5 / 14.8 MB |
  | 192 slow downloads of 4 MB: client peak, killed | 40.0 / 40.1 MB, 4 of 5 | 35.4 / 36.3 MB, 0 of 5 | 32.5 / 32.8 MB, 0 of 5 |
  | 192 short, completed downloads nobody reads: client peak | 35.7 / 35.9 MB | 31.3 / 31.8 MB | 28.3 / 28.6 MB |
  | One download, RTT 50 ms | 68.2 MB/s | 39.3 MB/s | 19.7 MB/s |
  | One download, RTT 150 ms | 24.1 MB/s | 12.2 MB/s | 6.1 MB/s |
  | 8 downloads, RTT 150 ms | 72.0 MB/s | 36.9 MB/s | 18.6 MB/s |

  At the default, one download at RTT 50 ms reads the same on `da42e75f`,
  `5ae2b3de` and `60e39569`: 67.9, 68.2 and 68.8 MB/s, six shuffled runs.
- A stream past the limit keeps what the server's stack was shown at the
  start: 16 KiB (`flowShownLimited`) for a client that announces more than
  the protocol default, 65535 before `5ae2b3de` and for a client that
  announces the default or no initial window at all. Forty streams of a Go
  client opened at once may be sent 4.3 MiB, not 4
  (`TestFlowSendWindowBoundsManyStreams`).
- A stack shown 16 KiB is forwarded no more ahead of the data it has sent
  than it had unused with 65535 shown (`09136349`, `downRelease`). A stream
  then opens with 212993 bytes of window, not 262144, and has its whole cap
  once data moves (`TestFlowSendWindowCreditFollowsData`). A lowering of the
  initial window that could be passed on before any data still can; one
  that comes while data lies unread is passed on in a range up to 49151
  bytes narrower than with 65535 shown. One under what the stack was
  forwarded gives the connection up as before, with the send window as
  without (`TestFlowSendWindowLoweringUnderForwarded`); `09136349` passed
  it on where the stack had used all it was forwarded, by showing the stack
  nothing, and `0a5f8c08` took that out again: a stream opened then could stay
  at no window for good.
  `09136349` against `a21c075d`, five shuffled runs: one download 70.0
  against 68.2 MB/s, at RTT 150 ms 24.1 against 23.5; eight downloads at
  RTT 150 ms 70.8 against 71.5; twenty slow readers 23.9 against 23.6 MB;
  192 short, completed downloads 36.3 against 35.7 MB; 192 slow downloads
  at 2 MiB 35.9 against 35.9 MB, none killed; at 100 Mbit/s the request
  beside eight downloads 66 / 253 against 66 / 259 ms and beside twenty
  slow readers 53 / 318 against 53 / 315 ms.
- On the stand an Xray client does not keep short, completed downloads in
  its own memory, governor on or off (192 downloads of 256 KiB read at
  1 KB/s each: 13 to 17 MB): it writes them on to the application's socket,
  into the kernel. `--app-buffer 32768` bounds that, as where the reader
  lives in the client's process. Then, five runs each, with 65535 shown
  (`323ca8b1`) against one frame (`a21c075d`):

  | | Stock | 65535 shown | One frame shown |
  | --- | --- | --- | --- |
  | 192 short, completed downloads nobody reads: client peak, killed | 40.0 / 40.1 MB, 5 of 5 | 40.6 / 41.0 MB, 5 of 5 | 35.7 / 36.5 MB, 0 of 5 |
  | 192 slow downloads of 4 MB: client peak, killed | 40.2 / 40.7 MB, 5 of 5 | 40.0 / 40.3 MB, 5 of 5 | 40.0 / 40.1 MB, 5 of 5 |
  | Twenty slow readers: client peak | | 23.6 / 23.6 MB | 23.8 / 23.9 MB |
  | 8 downloads, RTT 150 ms | | 71.0 MB/s | 71.8 MB/s |
  | Twenty slow readers, 100 Mbit/s: ping p50 / p95 | | 53 / 364 ms | 53 / 312 ms |

  At 100 Mbit/s the request beside eight downloads is p50 / p95 66 / 310
  against 66 / 268 ms (ten runs on `5ae2b3de`, p95 of single runs 157 to
  449 against 161 to 327).
- With three connections and hundreds of streams the default limit does
  not keep the client under 40 MiB, as the 192 slow downloads show. The
  windows are 15 MB of what the client then holds. Its runtime's own
  figures (`/debug/pprof/heap?debug=1` through a `metrics` listener, one
  run, client limit raised to 80 MiB, peak 43 to 45 MB): about 24 MB of
  live heap, the windows' 15 and 5 the client holds idle among them; 13 MB
  of heap the collector has not reclaimed yet (heap in use 37.4 MB, next
  collection at 39.0); and 7.8 MB of goroutine stacks, four goroutines to a
  session, against 2.1 MB with twenty. So about 60 KB of each open download
  is the client's own, stacks and heap, which no window reaches. `GOGC=25`
  brings the peak to 36.8 MB (heap in use 29.3), a memory limit of 30 MiB
  beside it to 33.2 MB at 2333 collections in the run. With twenty streams
  little is allocated after the start, the heap stays at 21.5 MB of a
  35.7 MB target, and `GOGC` changes nothing (23.6, 23.6, 23.2 MB, three
  runs each). A client buffer of its own (`policy.bufferSize` 0) changes
  nothing either.
- A stream may hold a frame, 16 KiB, whatever the stack is shown
  (`downRelease`, `9b302e11`). After a client's lowering of its window the
  stack can be shown less, or nothing; a stream opened then at a full limit
  had no window, or less than a Go client returns credit for, sent nothing
  that would bring credit of its own, and stayed there when the limit
  freed, whether the client or the server freed it. Now it is forwarded
  the frame (`TestFlowSendWindowFrameWhateverShown`,
  `TestFlowSendWindowServerFreesRoom`). `0a5f8c08` had a queue of such
  streams instead, walked after every frame from the client; it missed room
  the server freed, cost a walk of the queue for every frame where the room
  was under a quantum, and gave freed room to the oldest stream instead of
  the one whose reader reads. It is gone: a stream is looked at when its
  own client returns credit, as before (`TestFlowSendWindowIsReturned`),
  and connection credit looks at no stream, whatever their number
  (`TestFlowSendWindowConnectionCreditAllocs`,
  `BenchmarkFlowConnectionCredit`).
- `9b302e11` against `09136349`, five shuffled runs, median and range. MB/s
  read: one download 73.3 (67.3 to 75.1) against 72.5 (70.1 to 73.6), at
  RTT 150 ms 23.6 (23.5 to 24.3) against 24.0 (23.3 to 24.1); eight
  downloads 114.0 (109.8 to 114.1) against 113.9 (113.3 to 114.1), at
  RTT 150 ms 72.0 (71.3 to 72.8) against 72.6 (68.9 to 73.1). Client peak,
  median / worst: twenty slow readers 23.7 / 24.0 against 24.1 / 24.5 MB;
  192 short, completed downloads 36.4 / 36.8 against 36.1 / 36.6 MB; 192
  slow downloads at 2 MiB 34.9 / 36.5 against 35.4 / 36.0 MB, none killed,
  at 4 MiB killed 4 of 5 against 5 of 5. Request beside the load, p95,
  median of runs and range: beside eight downloads 117 (112 to 170) against
  107 (94 to 119) ms, at RTT 150 ms 452 (302 to 456) against 217 (168 to
  458); at 100 Mbit/s beside eight downloads 327 (244 to 379) against 333
  (228 to 366), beside twenty slow readers 308 (208 to 314) against 313
  (263 to 386). Throughput and memory do not differ. The p95 at RTT 150 ms
  read as worse in these five runs, 302, 307, 452, 456 and 456 ms against
  168, 170, 217, 301 and 458, so that pair was run again, twenty shuffled
  runs each. The p95 of a run falls near one, two or three round trips, on
  either build alike: under 250 ms in 4 runs against 5, from 250 to 380 in
  6 against 6, above in 10 against 9; median 406 against 349 ms, mean 363
  against 343; a rank-sum test gives z = -0.11. p50 is 154 ms on both, no
  request failed (506 and 509 sent), and the downloads read 72.4 against
  72.3 MB/s. The two builds do not differ, and five runs of this figure
  say nothing.
- Credit is not held to quanta any more: every piece a reader returns
  goes on as it comes, in both directions and at both ends, as before these
  changes, whether or not the stream still speeds up
  (`TestFlowUploadCreditNotHeld`, `TestFlowUploadConnectionCreditFollowsCap`,
  `TestFlowEndedUploadConnectionCreditNotHeld`,
  `TestFlowDownloadCreditNotHeld`, `TestFlowClientDownloadCreditNotHeld`).
  The reason is the start of a download that follows an upload on the same
  connection after an idle time. Measured with
  `testing/xhttpflow/slowreader/freshstart.py`: each run starts a client
  and a server, sends 30 MB up, then four times waits 3 s and times a
  download of 3 MB. Only the first of the four follows the upload; the
  other three follow a download of 3 MB on a connection of the same
  client, and the tables give the two apart.

  ```sh
  go build -o origin ./testing/xhttpflow/slowreader/origin
  F="sudo python3 testing/xhttpflow/slowreader/freshstart.py --origin ./origin --client /path/to/xray-v26.10.10"
  B="--server off=xray-e17be671 --h2flow off={\"enabled\":false} --server da42e75f=xray-da42e75f \
     --server 391e5f06=xray-391e5f06 --server 1e42fa62=xray-1e42fa62 --server e17be671=xray-e17be671"
  $F $B --before upload --connections 1 --runs 8      # 6 with --connections 3
  $F $B --before upload --connections 1 --runs 6 --server-cc bbr
  $F $B --before download --connections 1 --runs 3    # and --before nothing
  ```

  - Builds: `da42e75f`, before the quanta; `391e5f06`, which holds upload
    and download credit; `1e42fa62`, which holds only a server's download
    credit; `e17be671`, which holds none and whose `h2flow.go` is this
    code. Each from a clean checkout of its commit (`vcs.modified=false`),
    `GOOS=linux CGO_ENABLED=0 go build -tags http2legacy -trimpath`, Go
    1.27.2. "Off" is `e17be671` with the governor off.
  - Client: official Xray v26.10.10 (`701af60`), no governor, XHTTP over
    REALITY. Link: netem, 100 Mbit/s and 25 ms each way.
  - Host: linux/amd64 privileged container under Docker Desktop, kernel
    6.18.40.1-microsoft-standard-WSL2, AMD Ryzen 5 5600; a desktop with
    nothing else started on it.
  - Runs of all builds shuffled together. Seconds: median (least-most)
    and how many of the starts took over 0.7.

  The first start of a run, the one after `--before`:

  | | Off | `da42e75f` | `391e5f06` | `1e42fa62` | `e17be671` |
  | --- | --- | --- | --- | --- | --- |
  | Upload, CUBIC, one connection, 8 | 0.67 (0.67-0.68), 0 | 0.72 (0.69-0.76), 7 | 0.87 (0.83-1.21), 8 | 0.71 (0.71-0.73), 8 | 0.72 (0.69-0.77), 7 |
  | Upload, BBR, one connection, 6 | 0.38 (0.38-0.38), 0 | 0.42 (0.41-0.42), 0 | 0.42 (0.42-0.42), 0 | 0.41 (0.41-0.42), 0 | 0.41 (0.41-0.42), 0 |
  | Download, CUBIC, one connection, 3 | 0.39 (0.39-0.39), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 |
  | Nothing, CUBIC, one connection, 3 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 |
  | Upload, CUBIC, HyStart off, 4 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 | 0.53 (0.53-0.53), 0 |

  The three later starts of each run, after a timed download:

  | | Off | `da42e75f` | `391e5f06` | `1e42fa62` | `e17be671` |
  | --- | --- | --- | --- | --- | --- |
  | Upload, CUBIC, one connection, 24 | 0.63 (0.62-0.64), 0 | 0.64 (0.62-0.69), 0 | 0.68 (0.64-0.85), 10 | 0.64 (0.63-0.68), 0 | 0.64 (0.62-0.69), 0 |
  | Upload, CUBIC, three connections, 18 | 0.53 (0.53-0.68), 0 | 0.53 (0.53-0.73), 2 | 0.62 (0.53-1.01), 9 | 0.53 (0.53-0.72), 2 | 0.53 (0.53-0.72), 1 |
  | Upload, BBR, one connection, 18 | 0.30 (0.30-0.31), 0 | 0.30 (0.30-0.30), 0 | 0.30 (0.30-0.31), 0 | 0.30 (0.30-0.31), 0 | 0.30 (0.30-0.30), 0 |
  | Upload, BBR, three connections, 18 | 0.34 (0.30-0.76), 4 | 0.46 (0.30-0.80), 5 | 0.42 (0.30-0.68), 0 | 0.41 (0.30-0.80), 3 | 0.41 (0.30-0.80), 6 |

  With three connections the first start does not land on the connection
  that carried the upload (0.63 to 0.64 s on every build, CUBIC and BBR),
  and a later one may: the row pools connections with three histories. The
  rows with HyStart off were made with `/sys/module/tcp_cubic/parameters/hystart`
  set to 0 for the run and put back after it; `freshstart.py` does not
  touch that file, which is the host's.
  What these runs show. Under CUBIC a download after an upload starts
  slower than one after a download or after nothing, with the governor off
  as well, 0.67 against 0.53 s. The governor adds to that, 0.72 on
  `da42e75f`, and with upload credit held it adds more: 0.87, at least
  0.83, where no other build takes more than 0.77; the downloads after it
  on the same connection are still slower, ten of 24 over 0.7 s where no
  other build has one. With HyStart off every start of every build takes
  0.53 s. Under BBR on one connection the builds with the governor do not
  differ.
  What `ss -ti` shows on the server before the first start, in packets,
  CUBIC, one connection, eight runs:

  | | Off | `da42e75f` | `391e5f06` | `1e42fa62` | `e17be671` |
  | --- | --- | --- | --- | --- | --- |
  | Slow start threshold after the upload | 96-204 | 116-161 | 58-125 | 61-169 | 61-151 |
  | Congestion window after the upload | 259-267 | 202-241 | 64-125 | 213-239 | 199-239 |

  After the download instead the threshold is 528 to 630 on every build;
  after nothing, with HyStart off and under BBR a connection has none. The
  thresholds of the builds overlap. The windows do not: `391e5f06` ends
  the upload with half the window of the others, or a quarter, and its
  first start follows it run by run, 1.18 and 1.21 s with a window of 64,
  0.83 to 0.88 with 110 to 125, where the others have 199 to 267 and 0.67
  to 0.77 s. After the idle time the kernel cuts the window back towards
  the initial one and sets the threshold to the larger of the old one and
  three quarters of the window it had (`tcp_cwnd_restart`,
  `tcp_current_ssthresh`). That threshold is what the next download
  slow-starts up to, and it fits: about 150 to 200 packets for the four
  builds, 58 to 125 for `391e5f06`.
  An open hypothesis for why the window ends lower, read from
  `tcp_cubic.c` and `tcp_input.c` and not observed: while an upload runs
  the server sends the client little but credit, in small segments; the
  congestion window grows in slow start only while it is under twice the
  most packets recently out; HyStart then ends slow start there. Fewer credit segments,
  about a third as many with the quanta in the capture cited above, would
  leave a smaller window. Which of HyStart's two detectors fired was not
  looked at.
  What the quanta saved, `stand.py` at 1 Gbit/s with `--server-cc`, the
  same builds, client and host; CPU seconds per gigabyte, median and least
  to most of five shuffled runs:

  ```sh
  S="sudo python3 testing/xhttpflow/slowreader/stand.py --origin ./origin --client /path/to/xray-v26.10.10 --mbit 1000 --read-rate 0 --runs 5"
  B="--server da42e75f=xray-da42e75f --server 391e5f06=xray-391e5f06 --server 1e42fa62=xray-1e42fa62 --server e17be671=xray-e17be671"
  for cc in cubic bbr; do
    $S $B --server-cc $cc --workload uploads --readers 4
    $S $B --server-cc $cc --workload uploads --readers 1 --rtt 150
    $S $B --server-cc $cc --workload downloads --readers 8
    $S $B --server-cc $cc --workload downloads --readers 1 --rtt 150
  done
  ```

  | Server | `da42e75f` | `391e5f06` | `1e42fa62` | `e17be671` |
  | --- | --- | --- | --- | --- |
  | 4 uploads, CUBIC | 24.9 (22.9-27.2) | 21.3 (20.2-24.5) | 24.5 (23.7-26.7) | 24.9 (23.8-26.7) |
  | 4 uploads, BBR | 24.2 (22.8-25.0) | 22.1 (20.7-23.7) | 25.9 (23.5-27.4) | 23.6 (23.3-26.7) |
  | One upload, RTT 150 ms, CUBIC | 24.2 (22.5-24.8) | 22.7 (22.1-22.8) | 23.7 (23.2-24.7) | 23.3 (23.1-24.6) |
  | One upload, RTT 150 ms, BBR | 25.0 (23.1-27.3) | 22.6 (21.9-23.0) | 25.8 (23.0-31.2) | 24.7 (24.4-25.4) |
  | 8 downloads, CUBIC | 22.5 (20.7-24.6) | 24.7 (24.3-25.0) | 22.7 (22.1-25.4) | 23.7 (22.7-25.9) |
  | 8 downloads, BBR | 24.8 (20.1-25.1) | 25.4 (25.1-26.5) | 25.6 (25.2-26.4) | 26.0 (24.4-26.3) |
  | One download, RTT 150 ms, CUBIC | 22.3 (21.5-23.8) | 21.1 (20.5-21.7) | 20.4 (19.8-23.7) | 22.2 (21.1-22.7) |
  | One download, RTT 150 ms, BBR | 31.2 (31.0-34.6) | 33.3 (32.8-37.1) | 32.7 (32.3-33.3) | 33.5 (32.3-35.4) |

  | Client | `da42e75f` | `391e5f06` | `1e42fa62` | `e17be671` |
  | --- | --- | --- | --- | --- |
  | 4 uploads, CUBIC | 17.9 (15.7-19.0) | 14.1 (12.4-16.0) | 18.1 (17.2-19.5) | 19.1 (17.0-19.5) |
  | 4 uploads, BBR | 16.9 (15.4-17.7) | 14.3 (13.1-16.2) | 18.0 (16.3-19.2) | 16.2 (15.8-19.0) |
  | One upload, RTT 150 ms, CUBIC | 15.0 (14.3-15.6) | 12.7 (12.6-12.9) | 14.7 (14.3-15.3) | 14.5 (14.3-15.2) |
  | One upload, RTT 150 ms, BBR | 15.4 (14.6-17.4) | 12.7 (12.4-13.4) | 16.0 (14.3-19.9) | 15.1 (14.9-15.7) |
  | 8 downloads, CUBIC | 20.9 (18.4-22.2) | 22.8 (22.0-22.9) | 20.6 (19.7-22.8) | 21.7 (20.4-23.1) |
  | 8 downloads, BBR | 22.0 (18.1-22.6) | 23.3 (22.8-24.0) | 23.2 (22.9-23.8) | 23.3 (20.8-23.6) |
  | One download, RTT 150 ms, CUBIC | 16.7 (16.3-17.6) | 16.2 (15.8-16.3) | 16.0 (15.5-17.8) | 16.7 (16.1-17.2) |
  | One download, RTT 150 ms, BBR | 22.6 (22.5-25.8) | 24.9 (24.7-27.6) | 23.9 (23.3-24.7) | 25.2 (23.7-26.3) |

  The rates do not differ in any row (113.8 to 116.2 MB/s for four
  uploads, 36.5 to 37.0 for one, 111.2 to 114.2 for eight downloads, 23.6
  to 24.3 for one). On uploads the client of `391e5f06` spends 12.7 to 14.3
  s where the others spend 14.5 to 19.1, and on the single upload the
  ranges do not meet under either algorithm; that saving is the one these
  runs establish. The server's medians are 21.3 to 22.7 against 23.3 to
  25.9, but its ranges overlap the others' with four uploads and part
  from them, or nearly, only with one. Between `1e42fa62`
  and `e17be671`, which differ only in the held download credit, no row
  shows a difference outside the ranges. Twenty slow readers, CUBIC,
  `--client-limit-mb 40`: the client holds 23.3, 23.7 and 23.8 MB on the
  three builds with the limit, and `da42e75f` is killed five times of
  five. Held upload credit could come back for connections whose kernel
  does not use CUBIC, where these runs found no cost for it; that is not
  done.
  The send window under BBR, eight downloads, eight runs each, `da42e75f`,
  `e17be671` and `e17be671` with `maxConnectionSendWindow: -1`: server
  23.9 (21.4-25.1), 26.1 (25.4-27.0) and 24.9 (21.0-26.3) s per gigabyte;
  under CUBIC 23.4 (20.3-24.8), 24.3 (22.5-26.2) and 22.4 (20.8-24.2).
  Under BBR the limit is 9% over `da42e75f`, which also lacks the rest of
  the send window's change, with ranges that do not meet; against the same
  build without the limit it is 5% over, and the ranges overlap. Under
  CUBIC nothing is outside the ranges.
  Not looked for: the same start on a governed client, whose download
  credit was held. Not removed: what an upload does to the next download
  without the quanta, which `da42e75f` has too.
- A window follows the path model only once its reader has settled: no
  longer speeding up, and less than a quarter faster than the round before
  for two round trips in a row, counted from the round that ended its ramp
  (`settled`, `TestFlowWindowSettles`,
  `TestFlowWindowSlowGrowthThenLowRoundIsNotSettled`). Until
  `581a4d1b` one round trip without growth was enough. The end of a round may
  fall between the reader getting data and returning its credit; that
  round reads low and the next makes up for it. At the start of a stream
  the model then had that one small round to go by: the window fell from
  its 256 KiB to little over the 64 KiB it never goes under and grew back
  a quarter a round trip. It showed with a governor at both ends, where
  the client's window is the one that follows the model during a download.
  `freshstart.py` with `--client-h2flow '{"enabled":true}' --before
  nothing --starts 1 --idle 0.5 --connections 1`: each run is a new tunnel
  and one download of 3 MB, 100 Mbit/s, RTT 50 ms, the same build as
  client and server, blocks of 25 runs alternating between the builds.

  | | `e17be671` | `581a4d1b` |
  | --- | --- | --- |
  | Starts | 300 | 300 |
  | Median, least to most, s | 0.53, 0.53-0.83 | 0.53, 0.53-0.59 |
  | Over 0.7 s | 10, all 0.82 to 0.83 | 0 |
  | Over 0.55 s | 10 | 14, all 0.57 to 0.59 |

  The low round still ends the ramp, as before, and costs the start a
  round trip in those fourteen; it no longer costs six.
  What ends the ramp is not changed, on purpose. Requiring two flat rounds
  for that as well was tried first: a slow reader takes a little,
  irregularly, never has two such rounds, and had every larger round
  taken for a ramp. Twenty uploads into an origin that reads 100 KB/s
  each (the stand's default), five runs: the server's peak RSS rose from
  40.4 to 45.1 MB and the p95 of the request beside them from 425 to 643
  ms, in every run. With only the model waiting, twelve runs each: RSS
  41.5 and 41.1 MB, p95 467 (370-754) and 533 (368-753) ms, worst 0.75 s
  on both.
  Against an official client without a governor, `e17be671` and `581a4d1b`,
  five shuffled runs, medians: eight downloads 113.8 and 114.1 MB/s, at
  RTT 150 ms 72.3 and 71.3; one download at RTT 150 ms 24.1 and 24.1; four
  uploads 115.7 and 114.5; one upload at RTT 150 ms 36.7 and 36.9; twenty
  slow downloads with `--client-limit-mb 40`, the client holds 23.8 and
  23.5 MB; a download after an upload starts in 0.66 and 0.67 s. Builds,
  client and host as in the item above; `581a4d1b` was measured as its
  tree, built before the commit was made. A stream whose reader keeps
  taking irregular amounts now stays with `adjust` where it went to the
  model after its first flat round; the runs with slow readers above are
  what was looked at for that.
  What an observer sees of this change, against `e17be671`; nothing was
  captured for it, and the capture cited under "Credit quanta" is evidence
  for the withdrawal of the quanta, not for this:
  - Passive, on the path, TLS records only. The credit-release policy and
    the WINDOW_UPDATE frames are untouched; what moves is when a cap leaves
    `adjust` for the model. In the first round trips of a stream whose
    first rounds read low, a governed client's cap stays at 256 KiB or
    above where it fell to little over 64 KiB, so the server may send more
    DATA in those rounds: the start looks like the other 290 of 300 starts
    on `e17be671`, and nearer to a client without a governor, whose window
    never falls at a start. The same holds for an upload on a server whose
    kernel vouches for the path. A stream whose rounds stay irregular
    from the start keeps `adjust`'s windows until two flat rounds come:
    raised to twice a round when that is more, lowered by a quarter only
    after three low rounds and never under `init`. The model would have
    given it the fastest rate of its last ten rounds over the empty path's
    round trip, plus a quarter, within `init` and the limit. Once a window
    is modelled it is not judged again, as before.
  - A TLS terminator in front of the server sees the same frames with
    other window sizes at those moments.
  - An active prober that cannot authenticate. Under REALITY it goes to
    the target and never reaches the governor. On TLS it can open a
    stream: the governor tracks one from its HEADERS frame, the hub
    answers 200, and VLESS decides at the stream's first bytes. It gets no
    data on that stream, so it sees no download; what it can reach of this
    change is the upload side, the credit a server whose kernel vouches
    for the path returns for bytes the prober sends before it is refused.
  - Not measured: record counts and timing of the first round trips, on
    this change or against stock.
- A server scales its cuts against a queue by what they do to it
  (`flowEffect`, `cutGain`). It cut against any queue the kernel saw, and a
  queue that other traffic keeps full does not shorten when it does: pi took
  a download to `init` per round trip, about a megabit per second with a
  second of other traffic in the queue. Now, while the queue stands over a
  quarter more than pi's setpoint, each connection adds up the bytes pi and
  the cut at a long queue take off its caps, and notes once per round trip
  of the empty path how far the queue fell from its peak. Once the cuts come
  to a fifth of the caps of its downloads that took data within the last
  second, and what its kernel has in flight (`tcp_info` unacked times MSS)
  has come down as far, the queue's fall for that cut is the gain, within 0
  and 1; the measurement then starts afresh, and the gain stays until the
  next such cut, or goes back to 1 once the queue halves. pi's negative
  steps and the cut at a long queue are scaled by it; growth is not, and a
  cap whose reader takes what the cap gives follows the round trip by the
  rest of the gain, so the download keeps its rate beside a queue it cannot
  move. Only the controller's own cuts count: beside other traffic a loss
  that drops what is in flight, the caps following the round trip down and
  a dip of the other traffic's queue move together now and then, and read
  together as a cut that worked; cut after cut then took a download from
  10 to under 1 Mbit/s over a long burst. A download stays in the caps for a
  second after it last returned credit: one that slows returns it less
  often than once a round, and a round it missed would read as its cap cut.
  A small gain is kept as it is: a client's connections share its own queue,
  and each one's cut moves it by that connection's share. The queue halving
  gives the gain back: with only the controller's cuts to judge by, a small
  gain cuts little and is judged again late, and the neighbours' cuts that
  drain the queue are what shows it to be the client's own.
  pi's test for a reader that limits itself compares what the reader took
  in a round with the round's share of the cap, the cap over the round trip
  times the round: beside a queue of a second, a reader that takes all it
  is given copies less than a quarter of the cap per round of the empty
  path, and the cap was cut by a quarter every three rounds for it.
  `"h2Flow": {"queueCuts": false}` turns the cuts off for an inbound: pi
  and the cut at a long queue do not run, and the windows follow their
  readers alone (`H2FlowConfig.noQueueCuts`).
  The stand is `burst.py`: an official client, 60 Mbit/s at RTT 144 ms, a
  queue of five bandwidth-delay products, one download, four plain TCP
  downloads from the server's namespace for 20 s from the 10th second;
  three runs each, Mbit/s, median (least-most), on an earlier revision of
  this change; the acceptance below runs the burst on the head, eight runs
  each:

  ```sh
  python3 burst.py --origin ./origin --client ./xray-official \
      --server main=./xray-main --server stock=./xray-main --h2flow 'stock={"enabled": false}' \
      --server pr=./xray-pr --server pr-nocuts=./xray-pr --h2flow 'pr-nocuts={"enabled": true, "queueCuts": false}' --runs 3
  ```

  | | `28e1e458` | no governor | an earlier revision | `queueCuts: false` |
  | --- | --- | --- | --- | --- |
  | Before the burst | 56.5 | 57.1 | 56.5 | 57.0 |
  | Mean over the burst | 10.8 (10.7-10.8) | 41.3 (41.2-41.5) | 23.2 (22.7-23.4) | 36.2 (35.5-37.8) |
  | Mean over its second half | 0.8 (0.8-0.8) | 31.0 (30.6-31.0) | 16.5 (16.3-16.8) | 20.7 (20.4-25.5) |
  | Back at 4/5 after it | 4.0 (4.0-4.0) s | 2.0 s | 2.0 (1.5-4.0) s | 2.5 (2.0-3.0) s |

  With `--burst 90 --duration 120`, over the burst and over its second
  half: `28e1e458`, two runs, 2.5 (2.4-2.7) and 0.4; eight runs each, no
  governor 21.1 (18.8-24.9) and 14.1 (8.9-20.9), that revision 14.2
  (7.2-16.4) and 10.6 (3.5-13.3), back at 4/5 of the rate before in 1.8 s
  against 2.0 without the governor. Judged by every drop rather than the
  controller's own cuts the same eight runs gave 12.5 and 6.5 (0.6-9.5),
  back in 3.5 s. The stand's runs vary widely here; eight runs each is the
  least that told the builds apart. A client that credits in large steps,
  so that pi never governs its downloads, is not behind: Mihomo Meta on a
  similar stand (60 Mbit/s, RTT 144 ms, four flows for 90 s), three runs,
  got 13-16 and 8-14 on the fork's build of this change, 16-17 and 10-13
  without the governor.
  What it costs, as accepted after the third review: `28e1e458` against
  the head `cbf6fd81` (later commits change only tests and this file;
  the production code is the same), both built
  with Go 1.27.3, `CGO_ENABLED=0 go build -trimpath -tags http2legacy`;
  client official Xray v26.10.10 (go1.27.2); host a privileged
  linux/amd64 container under Docker Desktop on WSL2 (kernel 6.18.54), AMD
  Ryzen 5 5600, 12 threads. Runs alternate between the builds in shuffled
  order; medians (least-most where given) over the runs, p50/p95 of the
  request beside the load:

  ```sh
  O="--origin ./origin --client ./xray-official"
  S="--server base=./xray-28e1e458 --server head=./xray-cbf6fd81"
  python3 stand.py $O $S --workload downloads --readers 8 --read-rate 0 --runs 24
  python3 stand.py $O $S --workload uploads --readers 20 --runs 12
  python3 stand.py $O $S --workload downloads --readers 8 --read-rate 0 --mbit 1000 --runs 8
  python3 stand.py $O $S --workload downloads --readers 1 --read-rate 0 --rtt 150 --runs 8
  python3 stand.py $O $S --workload uploads --readers 4 --read-rate 0 --runs 8
  python3 stand.py $O $S --workload downloads --mbit 1000 --readers 20       --read-rate 100000 --client-limit-mb 40 --runs 6
  python3 burst.py $O $S --runs 8
  python3 burst.py $O $S --burst 90 --duration 120 --runs 8
  python3 freshstart.py $O $S --runs 6
  ```

  | Load | Runs | `28e1e458` | `cbf6fd81` |
  | --- | --- | --- | --- |
  | 8 downloads, 100 Mbit/s | 24 | 65.6/293 ms, 92 Mbit/s | 65.9/313 ms, 92 Mbit/s |
  | 8 downloads, 1 Gbit/s | 8 | 70.5/108 ms, 912 Mbit/s | 69.0/116 ms, 912 Mbit/s |
  | 1 download, RTT 150 ms | 8 | 190.5/354 ms, 84 Mbit/s | 190.5/354 ms, 84 Mbit/s |
  | 20 uploads into a slow origin | 12 | 52.5/578 ms | 52.6/466 ms |
  | 4 uploads | 8 | 82.6/251 ms | 91.1/187 ms |
  | 20 slow downloads, client limit 40 MB | 6 | 52.2/79 ms, client 23.8 MB, killed 0 | 52.2/115 ms, client 23.5 MB, killed 0 |
  | Burst 20 s, Mbit/s, over it / its second half | 8 | 10.8 (10.0-11.7) / 0.8 (0.8-0.9) | 25.6 (25.0-26.1) / 18.4 (17.1-19.2) |
  | Burst 90 s, the same | 8 | 2.7 (2.5-2.7) / 0.4 (0.4-0.4) | 16.8 (14.5-18.6) / 14.1 (9.7-15.6) |
  | First start after an upload / later starts | 6 | 0.64 / 0.53 s | 0.63 / 0.53 s |

  No request failed or took over 10 s in any run. Server CPU time, server
  peak RSS and the client's peak anonymous memory stay within 6% of
  `28e1e458` in every row. Two rows were over the line of a tenth this
  stand is judged by: the p95 of twenty slow downloads (79 against 115
  ms) and the p50 of four uploads (82.6 against 91.1). Both were run
  again with `2c733fb4`, the head before the third review, as a third
  build, twelve and sixteen runs, medians for `28e1e458`, `2c733fb4` and
  `cbf6fd81`: slow downloads p95 153, 158 and 181 ms; four uploads p50
  79, 81 and 82 ms, p95 198, 198 and 207. `28e1e458`'s own slow-download
  p95 moved from 79 to 153 ms between those rounds, so the slow downloads
  were then run as one interleaved set of thirty runs each:

  ```sh
  python3 stand.py $O $S --workload downloads --mbit 1000 --readers 20       --read-rate 100000 --client-limit-mb 40 --runs 30
  ```

  | Twenty slow downloads, 30 runs | `28e1e458` | `cbf6fd81` |
  | --- | --- | --- |
  | p95, median (quartiles; least-most) | 147 (94-206; 66-256) ms | 158 (107-209; 57-308) ms |
  | p50, median | 52.3 ms | 52.3 ms |
  | Requests failed or over 10 s | 0 of 1005 | 0 of 999 |
  | Client killed at its limit | 0 of 30 | 0 of 30 |

  The head's p95 is 8% over `28e1e458`'s, inside the line.
  Not covered by any of these: GC, goroutines, file descriptors, and the
  interface and TCP counters of either end.
  After the fourth review the server changes in three places: a first cut
  with nothing in flight is judged from the next round with some (C2),
  data past a stream's shown upload window is dropped, not forwarded, ahead
  of the reset (C3), client streams past a GOAWAY's last are not taken up
  (C5), and rebase also runs where a gain of none froze the caps over a
  queue that stood (C4). The client holds credit until it knows its
  server, and keeps the stack's window on a later SETTINGS (C1, C6). The
  server of `cbf6fd81` against the head `d46c6c88` (the commit after it
  changes only this file), same builds, client and
  host as the acceptance above, runs interleaved, medians:

  | Load | Runs | `cbf6fd81` | head |
  | --- | --- | --- | --- |
  | 8 downloads, 100 Mbit/s, p50/p95 | 24 | 65/307 ms | 66/305 ms |
  | 20 uploads into a slow origin, p50/p95 | 30 | 52/568 (quartiles 510-631) ms | 52/544 (421-619) ms |
  | 20 slow downloads, client limit 40 MB, p50/p95 | 12 | 52/177 ms, killed 0 | 52/106 ms, killed 0 |
  | Burst 20 s, over it / its second half | 12 | 25.6 / 18.2 Mbit/s | 25.3 / 18.7 Mbit/s |
  | Burst 90 s, the same | 8 | 15.8 / 11.7 Mbit/s | 15.9 / 13.8 Mbit/s |

  The uploads were first run twelve times each, p95 455 against 549 ms
  (rank test z 1.27); the thirty above are one interleaved set run after
  them. No request failed or took over 10 s in any of these.

  The RTT-step stand (`rtt/burstrtt.py`, 20 to 120 ms at the 10th second
  for 60 s, no other flows), official client, three runs each, Mbit/s over
  the step, against the head before C4 and with the governor off:

  | Link | before C4 | head | no governor |
  | --- | --- | --- | --- |
  | 100 Mbit/s | 15.4 (11.2-47.6) | 89.2 (89.2-89.3) | 94.7 |
  | 200 Mbit/s | 24.0 (23.9-37.3) | 178.5 (178.4-180.5) | 188.6 |

  At 50 Mbit/s, where the cap is near init before the step, C4 changes
  nothing: 44.4 against 44.4 and 44.3 on the builds with three quarters and
  with none of the standing queue, 47.0 without the governor.

  The gain of none counts only where the queue's least over the window is
  at nine tenths of its most. At three quarters, a 20 s burst of other
  traffic was taken for the path once a run, its gain was learnt again and
  the download cut anew: over twelve runs its second half fell from 18.2
  to 15.2 Mbit/s; at nine tenths it is 17.9 against 18.0. With 64
  connections and 128 downloads at 1 Gbit/s, twelve runs, p50/p95 149/280
  before C4 and 148/321 ms with it (rank test z -0.23 and 0.81); a logging
  build counted 65 rebases over four runs there, 9 of them through the gain
  of none, against 17 of 85 at three quarters.
  A governed client behind a governed server, against the same server
  (`both.sh`): eight downloads p50 65 ms in 9 of 12 runs, as with the
  official client and the client before C1; the client holding 23.9 MB
  under a 40 MB limit; burst 20 s 25.3 / 18.1 Mbit/s; RTT step 20 to 120
  ms 44.5. Showing the stack's window less the credit forwarded ahead,
  tried first for C1, kept the connection but put the queue beside eight
  downloads at 180-290 ms. Toward a server without the governor the hold
  costs the first request of a connection a round now and then: later
  starts after 3 s idle at 0.64-0.68 s in 9 of 18 against 3 of 18 (0.53
  s otherwise; rank test z 0.98), eight downloads p50 91 against 100 ms (z
  1.13).
  After the fifth review the queue stands for rebase where its least over
  the window is no more than a tenth of its most or 20 ms under it (C7);
  the connection credit of a frame dropped past a stream's window goes back
  to the client (C8), and nothing inside an open header block is dropped
  (C9). A logging build of `e627b971` wrote every check, three runs or one
  of each: on the RTT step with netem jitter (`--step-jitter`, 0 to 16 ms
  each way) the smoothed queue spread by up to 14 ms; a 20 s burst of other
  traffic by 38 to 370 ms while it fills; with 64 connections the server's
  own queue by 12 to 15 ms at times, the median 17. The 20 ms takes these
  64-connection checks as well (46 of 85 against 9), where the cuts do
  nothing and 45 checks rebase from pinned caps anyway. `e627b971`
  against the head, runs interleaved, medians:

  | Load | Runs | `e627b971` | head |
  | --- | --- | --- | --- |
  | RTT step 20 to 70 ms, jitter 16 ms, 200 Mbit/s, over the step | 3 | 166.2 (125.2-179.5) | 180.4 (166.9-180.6) Mbit/s |
  | The same at 100 Mbit/s | 3 | 79.1 (70.4-88.8) | 90.1 (89.9-90.2) Mbit/s |
  | 64 connections, 128 downloads, 1 Gbit/s, p50/p95 | 12 | 164/273 ms | 160/241 ms |
  | Burst 20 s, over it / its second half | 12 | 25.4 / 17.8 Mbit/s | 25.4 / 18.0 Mbit/s |
  | Burst 90 s, the same | 6 | 15.2 / 11.5 Mbit/s | 16.7 / 12.5 Mbit/s |
  | 8 downloads, 100 Mbit/s, p50/p95 | 24 | 66/274 ms | 66/282 ms (z 0.72 / 0.85) |

  Both recover in the step's second half, 189.4 and 94.6 Mbit/s. Eight
  downloads made no check at all in the logging build; their p50 was over
  100 ms in 4 of 24 runs before and 6 of 24 after.
  Tried on the way and dropped, each for a regression of eight downloads at
  100 Mbit/s, whose request beside them has 65 ms at p50 on `28e1e458`, or
  for not holding the burst:
  - A verdict per client address: once what the client's connections have
    in flight and unacked halved and the queue did not come down by a
    quarter, the queue counted as foreign and the cuts stopped. It held the
    burst at 20.7 but split eight downloads into runs at 65 ms and runs at
    200 to 390.
  - A server-wide reference: every download's credit moved ±15% by chips
    of random length, and a queue that followed them counted as the
    server's own. Against past stretches of the reference as the noise
    floor, an own queue followed it in 80 to 100% of six-second windows on
    a clean link and in 3 to 18% on jittery or cellular ones; the
    modulation alone took eight downloads to 80-101 ms, and at 64
    connections 20 and 27 of 128 downloads stopped.
  - A dead zone under a quarter, the RTT variance taken off the queue's
    fall, and a gain of none held until a test cut: each killed the small
    gains of connections sharing an own queue (80 to 160 ms).
  - The queue smoothed again before the comparison: it lags what is in
    flight by rounds, and a slow reader read gains of a half for cuts that
    had landed (p95 284 against 187 ms).
  What an observer sees of this change:
  - Passive, on the path. Where the server's own data makes the queue,
    nothing changes. Beside traffic that keeps a queue full the server's
    downloads hold their rate rather than fall to `init`; the windows grow
    and shrink with the round trip. Nothing is sent that the reader did not
    credit, no probe or modulation is added, and the state is per
    connection.
  - An active prober that cannot authenticate gets no data on a stream, so
    it starts no download and reaches no queue.
  - TLS handshake and fingerprint: not touched. The governor wraps the
    listener TLS or REALITY returns and sees only the HTTP/2 frames inside
    the connection; no TLS, REALITY or ALPN setting changes. What an XHTTP TLS
    listener answers to probes that never reach HTTP/2 (TLS, ALPN,
    HTTP/1.1) is compared byte for byte with the governor on and off
    (`TestFlowListenerAnswersProbesLikeStock`).
  - Connection lifecycle: an HTTP/1.1 request over the header limit is
    answered and closed as on stock TLS, close_notify right after the
    answer (`TestFlowListenerClosesLikeStock`); a client that sends past
    the windows it was shown gets the stock answers, the stream reset with
    FLOW_CONTROL_ERROR past a stream's window and the connection ended past
    the connection's (`TestFlowClientPastShownWindow`).
  - Malformed input: malformed SETTINGS get the same answer from a governed
    server as from stock (`TestFlowMalformedSettingsGetStockErrors`); a
    malformed SETTINGS ACK reaches a governed client's stack whole, for the
    stack to raise, and is not taken for the ACK of the governor's own
    SETTINGS (`TestFlowClientMalformedOwnedAckReachesStack`).
  - These tests check answers and closes, not packet sizes or timing.
  - Not measured: record counts and timing beside a foreign queue, against
    stock or `28e1e458`; links whose other traffic is not bulk TCP; BBR on
    the server.
- A governed server's first PING, sent with its first SETTINGS, carries
  `flowPingTag` (`0x6b7a3f91`) in its upper half; its lower half and every
  later PING are random. A governed client takes that PING, and no other
  early one, for a server that governs its downloads (`peerGoverned`).
  Under REALITY a prober that cannot authenticate goes to the target and
  never sees it. On plain TLS any HTTP/2 client sees it before its first
  request: three probe connections got `6b7a3f91b3770d97`,
  `6b7a3f91060ebdff` and `6b7a3f9180f4a67c`, where `28e1e458` sends random
  data. The early PING alone already tells a governed server from stock
  there; the tag makes it a mark of this governor. Any rule the client
  could tell the tag by without a secret the two ends share, a prober
  could tell it by as well, so the tag stays, and h2Flow on plain TLS
  exposes it.
- A client that has returned nothing in small steps when the guard fires has
  the limit lifted for that connection (`TestFlowGuardLiftsSendWindow`), or a
  client that credits at half its window would stop for good. The lift is
  for good, and it does not take a client at its limit: a connection whose
  reader pauses before a Go client's first credit, which waits for 4 KiB
  read, loses the limit with the client holding half of it, and keeps none
  when the reader goes on and credit comes in small steps
  (`TestFlowGuardLiftIsForGood`). Bringing the limit back on small credit
  would stop a client that returns it per stream: one stream may credit in
  small steps while the others wait for half a window.
- The client is Xray for linux/amd64, not a phone; kernel socket buffers
  are not counted, and a spike shorter than 50 ms can be missed.
- CPU differences on downloads are inside the noise of five runs; the
  upload rows repeat across runs.
- `TestFlowChainedGovernorsSlowReaders` failed about one run in a hundred
  because the server's cap had not fallen when the downloads ended: it
  judged a state it had not reached. Its readers now pause after every
  read until a cap has been seen to fall at both ends, and
  `XRAY_FLOW_TEST_SEED` sets the seed (`9b302e11`): 0 of 150 runs, 300 subtests.
- `TestFlowChainedGovernorsSlowReaders` stopped once in a full `-race` run
  of `154e636c` in review. It has not come back: 150 `-race` runs of it
  alone, with and without the send window, on a tree that differs from
  `323ca8b1` only in how the send window is totalled, 40 more and a full
  `-race` run of the package on `323ca8b1` pass. The cause of that one stop is not
  known; the test now logs its seed and both ends' counters if it happens
  again.

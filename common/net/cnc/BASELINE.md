# Connection baseline

Measurements of `cnc.Connection`, the connection over a pair of buffer
readers and writers.

## Read of a connection for a UDP destination (2026-11-12)

`BenchmarkDatagramConnectionRead` (`datagram_performance_test.go`) reads one
datagram per op from a connection made with `ConnectionOutputMultiUDP` into a
buffer that holds it: 1500 bytes, as a QUIC transport or a UDP mask reads
through `FakePacketConn` over `sockopt.dialerProxy`, and 8193 bytes, as the
SOCKS, Shadowsocks, DNS and WireGuard outbounds read their replies. The link
below returns one datagram per read in a pooled buffer.

The change it guards: `Read` drops a datagram longer than the buffer and
returns the next, where it copied the start of the datagram as a UDP socket
does (`buf.SplitFirstBytes`). A datagram that fits takes one more comparison
and a call through the connection's own splitter.

### Conditions

- Before: `d4da349a` with the benchmark file. After: the same with the change
  to `connection.go`, as committed.
- Go 1.27.3 linux/amd64, AMD Ryzen 7 5700X (16 threads), kernel
  6.18.58.1-microsoft-standard-WSL2. WSL2 exposes no CPU governor. No build,
  test or other benchmark ran meanwhile; the load average was 0.74 at the
  end.
- One test binary per side, built with
  `GOFLAGS=-tags=http2legacy go test -c ./common/net/cnc`, and six samples of
  each, taken in turn so that both sides share the host's drift:

  ```sh
  ./cnc.test -test.run '^$' -test.bench '^BenchmarkDatagramConnectionRead$' \
    -test.benchmem -test.count=1
  ```

### Results

| datagram into buffer, bytes | side | median ns/op | range ns/op | B/op | allocs/op |
| --- | --- | --- | --- | --- | --- |
| 64 into 1500 | before | 51.18 | 49.21-55.33 | 56 | 2 |
| 64 into 1500 | after | 52.18 | 51.21-63.42 | 56 | 2 |
| 1200 into 1500 | before | 66.43 | 65.41-73.08 | 56 | 2 |
| 1200 into 1500 | after | 69.00 | 66.72-81.22 | 56 | 2 |
| 1200 into 8193 | before | 66.68 | 65.07-75.52 | 56 | 2 |
| 1200 into 8193 | after | 69.81 | 66.17-75.89 | 56 | 2 |
| 8192 into 8193 | before | 187.25 | 183.50-218.30 | 56 | 2 |
| 8192 into 8193 | after | 196.35 | 185.10-230.50 | 56 | 2 |

The 56 bytes in 2 allocations are the benchmark link's `MultiBuffer` and
`Buffer`; `Read` allocates nothing on either side. The medians are 1.0 to 3.1
ns apart up to 1200 bytes and 9.1 ns apart at 8192, the after side slower in
every row, but the ranges overlap in every row, so the run shows a direction
and no more. An earlier run of the same kind, before `Read` took its check
for an empty buffer, had the 64-byte row at 52.67 against 56.12 ns with
ranges that did not overlap, and the other rows within 2.3 ns. Together: a
read of a datagram that fits costs a few nanoseconds more, at most 7% of a
read that is all bookkeeping.

### Limitations

- The link is a buffer in memory. A real one adds a pipe, and the packet's
  encryption and socket write on the other outbound, each far above a few nanoseconds, so
  this is no throughput claim for QUIC over `dialerProxy`; no process
  benchmark covers that path.
- One host, under WSL2. A comparison on another host needs both sides run
  there.

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
  to `connection.go`.
- Go 1.27.3 linux/amd64, AMD Ryzen 7 5700X (16 threads), kernel
  6.18.58.1-microsoft-standard-WSL2. WSL2 exposes no CPU governor. No build,
  test or other benchmark ran meanwhile; the load average was 0.26 at the
  start.
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
| 64 into 1500 | before | 52.67 | 49.87-53.75 | 56 | 2 |
| 64 into 1500 | after | 56.12 | 54.88-79.06 | 56 | 2 |
| 1200 into 1500 | before | 67.42 | 65.66-73.64 | 56 | 2 |
| 1200 into 1500 | after | 67.90 | 66.89-70.80 | 56 | 2 |
| 1200 into 8193 | before | 68.58 | 66.58-71.34 | 56 | 2 |
| 1200 into 8193 | after | 68.99 | 67.24-71.67 | 56 | 2 |
| 8192 into 8193 | before | 192.00 | 185.30-208.00 | 56 | 2 |
| 8192 into 8193 | after | 194.30 | 185.20-198.50 | 56 | 2 |

The 56 bytes in 2 allocations are the benchmark link's `MultiBuffer` and
`Buffer`; `Read` allocates nothing on either side. At 1200 and 8192 bytes the
ranges overlap and the medians are within 2.3 ns: no difference shows. At 64
bytes the ranges do not overlap and the read costs 3.5 ns more by the
medians, about 7% of a read that is all bookkeeping; one sample of the six
was an outlier at 79 ns.

### Limitations

- The link is a buffer in memory. A real one adds a pipe, and the packet's
  encryption and socket write on the other outbound, each far above 3.5 ns, so
  this is no throughput claim for QUIC over `dialerProxy`; no process
  benchmark covers that path.
- One host, under WSL2. A comparison on another host needs both sides run
  there.

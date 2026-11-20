# Buffer reader baseline

Measurements of the datagram readers of `common/buf`.

## DatagramReader and ReadDatagram (2026-11-12)

`datagram_performance_test.go` keeps three benchmarks of the primitives that
read a UDP datagram whole:

- `BenchmarkDatagramReaderRead`: a steady-state read of one datagram by
  `DatagramReader`, which reads into its scratch of `Size`+1 bytes and copies
  the datagram into a pooled `Buffer`, next to `PacketReader`, which reads into
  the `Buffer` and which the SOCKS, Shadowsocks and DNS outbounds used before.
  One op is one datagram returned and released. In `9000+1200` the reader also
  drops a datagram longer than `Size` before the one it returns;
  `PacketReader` would return that one cut, so the case has no other side.
- `BenchmarkDatagramReaderCreate`: what a session pays for its reader. SOCKS
  and Shadowsocks create one per UDP session, DNS one per handler.
- `BenchmarkReadDatagram`: a read of one framed datagram from a stream that
  holds it, as the VLESS, VMess, Trojan, Mux.Cool and XUDP readers call it.

### Conditions

- Source `40706516` with the benchmark file and the fixes of the second
  review in the worktree; none of them changes `DatagramReader`,
  `PacketReader` or `ReadDatagram`.
- Go 1.27.3 linux/amd64, AMD Ryzen 7 5700X (16 threads), kernel
  6.18.58.1-microsoft-standard-WSL2. WSL2 exposes no CPU governor. No build,
  test or other benchmark ran meanwhile; the load average was 1.95 at the
  start.
- Command, six samples:

  ```sh
  GOFLAGS=-tags=http2legacy go test ./common/buf -run '^$' \
    -bench '^Benchmark(DatagramReader(Read|Create)|ReadDatagram)$' \
    -benchmem -count=6 -timeout 600s
  ```

### Results

Per datagram, `BenchmarkDatagramReaderRead`:

| datagram, bytes | reader | median ns/op | range ns/op | B/op | allocs/op |
| --- | --- | --- | --- | --- | --- |
| 64 | `PacketReader` | 46.31 | 46.12-47.02 | 56 | 2 |
| 64 | `DatagramReader` | 48.70 | 48.51-49.39 | 56 | 2 |
| 1200 | `PacketReader` | 57.09 | 55.83-58.83 | 56 | 2 |
| 1200 | `DatagramReader` | 68.21 | 66.99-72.20 | 56 | 2 |
| 8192 | `PacketReader` | 128.55 | 108.00-192.10 | 56 | 2 |
| 8192 | `DatagramReader` | 172.65 | 168.00-208.10 | 56 | 2 |
| 9000, then 1200 | `DatagramReader` | 188.35 | 180.30-200.20 | 56 | 2 |

Per session, `BenchmarkDatagramReaderCreate`:

| reader | median ns/op | range ns/op | B/op | allocs/op |
| --- | --- | --- | --- | --- |
| `PacketReader` | 13.48 | 12.84-14.25 | 16 | 1 |
| `DatagramReader` | 1389 | 1114-1524 | 9472 | 1 |

Per datagram, `BenchmarkReadDatagram`:

| datagram, bytes | median ns/op | range ns/op | B/op | allocs/op |
| --- | --- | --- | --- | --- |
| 1200 | 53.55 | 51.26-57.47 | 48 | 1 |
| 8192 | 107.00 | 98.68-133.20 | 48 | 1 |
| 8193 | 374.90 | 355.70-390.20 | 169 | 4 |
| 16384 | 717.10 | 683.20-772.10 | 169 | 4 |
| 32768 | 1380.50 | 1368-1475 | 266 | 6 |
| 32769 | 1487 | 1449-1499 | 371-375 | 8 |
| 65535 | 2755 | 2742-2765 | 538-542 | 11 |

`DatagramReader` allocates per datagram what `PacketReader` does, 56 bytes in
2 allocations for the `MultiBuffer` and its `Buffer`; the payload comes from
the pool on both sides. Its copy costs 2 ns for 64 bytes and 11 ns for 1200,
outside the ranges of `PacketReader`. At 8192 bytes the medians are 44 ns
apart, but the ranges overlap, so that row shows no more than the direction.
The reader itself takes one allocation of 9472 bytes per session, the size
class of its 8193-byte scratch, where `PacketReader` takes 16.

`ReadDatagram` up to `Size` reads into one pooled `Buffer`, as the readers
did before. Above it, a datagram costs the regular buffers it arrives in, the
slice that holds them, and the copy into one buffer from `bytespool`: 4
allocations of 169 bytes for two parts, 11 of about 540 for eight.

### Limitations

- The socket of these benchmarks is a copy in memory, so they show the
  reader's own cost, not its share of a `recvfrom` call, which costs more than
  the copy. They are no throughput claim for a UDP session.
- The test binary logs at debug level, so `9000+1200` includes the check of
  `net.DropLog` and one log line a second.
- One host, under WSL2. A comparison on another host needs both sides run
  there.

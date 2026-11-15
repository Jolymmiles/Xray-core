# Hysteria UDP reader baseline

## General UDP address reuse

`UDPReader` parses an IPv4 literal from the message bytes without allocating,
and caches the last known-domain address. Any other address (an IPv6 literal,
an IPv4-mapped IPv6 literal, a domain the known-domain parser declines) went
through `parseUDPDestination(string(address))` on every packet: a string
allocation, `net.SplitHostPort` and `net.ParseAddress`. `UDPReader` now keeps
the last such address and its parsed destination, and a packet to the same
address reuses them, as Hysteria 2.14.0 reuses the address of the previous UDP
message (`ParseUDPMessageReuseAddr`, apernet/hysteria `c2b181e0`). The cached
string and destination own their memory; nothing aliases the packet buffer.

Guarded by `udp_reader_address_cache_test.go`: a repeated general address
allocates no more than a repeated IPv4 address on `ReadMultiBuffer` and
`readFromPacket`, destinations follow address and port changes across the IPv4,
domain and general paths, and a malformed address neither poisons the cache
nor stops the reader.

### Conditions

- Baseline: `def50474` with `proxy/hysteria/client.go` at `HEAD` and the new
  test file; candidate: the same tree with the cache. Both on branch
  `chore/sync-hysteria-2.14.0`, which also bumps apernet/quic-go (not on this
  path).
- Go 1.27.3, linux/amd64, `GOFLAGS=-tags=http2legacy`.
- AMD Ryzen 7 5700X, 16 logical CPUs, WSL2 kernel 6.18.58.1 (no cpufreq
  governor exposed). No builds, tests or other benchmarks ran during the
  measurement; load average 0.46.
- Both test binaries were built with `go test -c ./proxy/hysteria`. Ten rounds,
  each running the baseline and then the candidate once:

```sh
"$binary" -test.run '^$' \
  -test.bench '^BenchmarkUDPReader(ReadMultiBuffer(IPv6|IPv6Small|Domain)?|ReadFrom(IPv6)?)$' \
  -test.benchtime 1s -test.count 1 -test.benchmem -test.cpu 1
```

### Results

Medians of ten samples, with the range.

| Benchmark | Before ns/op | After ns/op | Change | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| `BenchmarkUDPReaderReadMultiBufferIPv6` | 183.5 (181.3–187.4) | 90.9 (89.1–96.2) | −50.4% | 88 → 48 | 3 → 1 |
| `BenchmarkUDPReaderReadMultiBufferIPv6Small` | 173.4 (170.9–176.8) | 79.9 (78.5–86.3) | −53.9% | 88 → 48 | 3 → 1 |
| `BenchmarkUDPReaderReadFromIPv6` | 154.5 (153.4–159.7) | 70.7 (70.3–74.9) | −54.2% | 64 → 24 | 3 → 1 |
| `BenchmarkUDPReaderReadMultiBuffer` (IPv4) | 103.7 (103.0–105.7) | 104.8 (102.2–109.4) | +1.0% | 48 → 48 | 1 → 1 |
| `BenchmarkUDPReaderReadMultiBufferDomain` | 95.8 (94.8–97.2) | 95.9 (91.9–99.9) | +0.1% | 48 → 48 | 1 → 1 |
| `BenchmarkUDPReaderReadFrom` (IPv4) | 85.1 (84.0–86.9) | 84.4 (84.0–86.5) | −0.8% | 28 → 28 | 2 → 2 |

The allocation left in `ReadMultiBuffer` is the packet's `buf.Buffer`, which
every address family pays.

### Limitations

- These are isolated microbenchmarks of the reader with a single repeated
  address. A flow that alternates between two general addresses on one
  Hysteria UDP session misses the cache every packet and costs what it did
  before, plus one string comparison.
- Process gate: `TestHysteriaProcessClientMatrix` (plain/Gecko × Xray,
  sing-box, Mihomo, three runs) passed 18/18 with the change, but its UDP echo
  is an IPv4 target, so no process cell sends UDP to an IPv6 address.
- WSL2 is not a Linux server host; no process-level throughput comparison was
  run, so no packets-per-second claim is made.

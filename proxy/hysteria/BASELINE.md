# Hysteria UDP reader baseline

## General UDP address reuse

`UDPReader` parses an IPv4 literal from the message bytes without allocating,
and caches the last known-domain address. Any other address (an IPv6 literal,
an IPv4-mapped IPv6 literal, a domain the known-domain parser declines) went
through `parseUDPDestination(string(address))` on every packet: a string
allocation, `net.SplitHostPort` and `net.ParseAddress`. `UDPReader` now keeps
the last four such addresses with their parsed destinations, replaced first in
first out, and a packet to one of them reuses its destination. Hysteria 2.14.0
reuses only the address of the previous UDP message
(`ParseUDPMessageReuseAddr`, apernet/hysteria `c2b181e0`), and keeps it per
QUIC connection, so concurrent UDP sessions of one client displace it; the
`UDPReader` cache belongs to one UDP session. The cached strings and
destinations own their memory; nothing aliases the packet buffer.

Guarded by `udp_reader_address_cache_test.go`: a repeated general address, and
a session cycling through two to four IPv6 targets, allocate no more than a
repeated IPv4 address; destinations follow address and port changes across the
IPv4, domain and general paths and across evictions; a malformed address
neither poisons the cache nor stops the reader.

### Conditions

- Single-address measurement: baseline `def50474` with
  `proxy/hysteria/client.go` at `HEAD` and the new test file; candidate: the
  same tree with a one-entry cache, the first version of this change. Both on
  branch `chore/sync-hysteria-2.14.0`, which also bumps apernet/quic-go (not
  on this path).
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

### Several addresses per session

A one-entry cache misses on every packet when one session sends to several
IPv6 peers in turn (STUN/ICE, games, a full-cone socket with a few peers).
`BenchmarkUDPReaderReadMultiBufferIPv6Alternating` cycles one session through
`targets` IPv6 destinations with 64-byte payloads. Variants: no cache (`HEAD`
before this change), one entry, four entries first in first out (adopted),
eight entries, and four entries checking the last hit first. Test binaries
built with `go test -c ./proxy/hysteria`, run in rounds that execute each
variant once with the command above and
`-test.bench '^BenchmarkUDPReader(ReadMultiBuffer(IPv6|IPv6Small)?|ReadMultiBufferIPv6Alternating)$'`.
Same host and conditions; load average 0.06–0.08.

Nine rounds, one entry against four (adopted) and four checking the last hit
first; medians in ns/op with the range, allocations per operation:

| Benchmark | One entry | Four entries | Four, last hit first |
| --- | ---: | ---: | ---: |
| `ReadMultiBuffer` (IPv4) | 102.8 (101–105), 1 | 104.0 (102–106), 1 | 102.5 (100–104), 1 |
| `ReadMultiBufferIPv6` | 90.7 (89–121), 1 | 89.5 (88–95), 1 | 90.9 (90–111), 1 |
| `ReadMultiBufferIPv6Small` | 79.5 (79–81), 1 | 81.5 (80–84), 1 | 80.8 (80–82), 1 |
| `IPv6Alternating/targets=1` | 80.5 (79–81), 1 | 81.4 (80–84), 1 | 82.3 (82–84), 1 |
| `IPv6Alternating/targets=2` | 198.6 (195–203), 3 | 82.0 (80–84), 1 | 83.7 (82–85), 1 |
| `IPv6Alternating/targets=3` | 197.7 (194–200), 3 | 81.4 (81–83), 1 | 83.0 (82–85), 1 |
| `IPv6Alternating/targets=4` | 194.1 (192–200), 3 | 81.7 (81–84), 1 | 83.1 (81–85), 1 |
| `IPv6Alternating/targets=8` | 195.7 (193–206), 3 | 197.7 (197–200), 3 | 203.3 (200–213), 3 |

An earlier seven-round run of the same binaries plus no cache and eight
entries gave, for `targets=1/2/4/8`: no cache 194.1/194.2/186.0/188.0 ns (3
allocations each), eight entries 80.6/80.8/80.7/81.7 ns (1 allocation each).

Four entries remove the allocations and halve the time for two to four
targets. With one target they cost 1–2 ns on 64-byte packets, within
overlapping ranges, and nothing on 1100-byte packets. Checking the last hit
first did not recover that cost and was dropped. Eight entries cover more
peers at the same single-target cost, but a cycle longer than the cache pays
a comparison per entry on every miss; four was kept as the smaller bound.

### Process level

`TestHysteriaUDPPerformanceAgainstBaseline` (`common/singmux/TESTING.md`)
compares baseline server `e50daf2e` with candidate `261e3e8c`. Both run behind
the same candidate Xray Hysteria client, which sends 64-byte packets through
one SOCKS UDP association, at most 32 in flight, to UDP echoes. There were
nine alternating rounds of 200,000 packets after a full-size settling load,
with no losses. Same host as above; the test builds both servers with `go
build -trimpath -buildvcs=false` and `GOFLAGS=-tags=http2legacy`. Medians with
the range:

| Targets | Server CPU ns/packet before | After | Change | pps before | After |
| --- | ---: | ---: | ---: | ---: | ---: |
| IPv4 (control, unchanged path) | 32781 (32680–32917) | 32730 (32517–32878) | −0.2% | 83934 | 83767 |
| One IPv6 | 33864 (33389–34693) | 32954 (32832–33312) | −2.7% | 80545 | 83407 |
| Four IPv6 in turn | 32354 (32109–32504) | 31679 (31520–31921) | −2.1% | 80994 | 81343 |

Server CPU per packet covers the whole round trip: QUIC, the upload reader,
the download writer, the runtime, and its idle spinning in this closed loop.
The IPv6 ranges do not overlap, and an earlier run with the same samples gave
−1.4% (one target) and −2.1% (four), while the IPv4 control stayed within
noise. The saving, 700–900 ns per packet, is larger than the
reader's 100 ns because two fewer allocations per packet also mean less
garbage collection; the run does not separate the two. Delivered pps moves
within noise: the closed loop is bounded by the whole path, client included,
so server CPU per packet is the figure this change affects. A first attempt
with 40,000-packet samples and no settling load swung by a factor of 2.7 in
pps on identical code and is not used.

### Limitations

- A session cycling through more general addresses than the cache holds misses
  on every packet and costs a few percent more than without a cache (the
  comparisons with every entry), in the microbenchmark; a DHT or another
  socket talking to dozens of peers gets no benefit.
- `TestHysteriaProcessClientMatrix` (plain/Gecko × Xray, sing-box, Mihomo)
  sends UDP to six IPv6 echoes per cell: one repeated, three in turn and all
  six in turn, past the four cached entries. It checks that each reply comes
  from its own target.
- The process numbers come from WSL2 on a desktop CPU: a Linux kernel, but a
  virtualized one on a host that is not a server. They show the relative
  change; they are not server capacity figures.

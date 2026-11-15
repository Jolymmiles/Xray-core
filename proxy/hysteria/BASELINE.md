# Hysteria UDP reader baseline

## IPv6 literals parsed from the message bytes

`UDPReader` parses an IPv4 literal straight from the message bytes into a
`[4]byte` and stores it in the packet buffer's slab
(`buf.SetManagedUDPIPv4`), so the address costs no allocation. Before this
change an IPv6 literal went through `parseUDPDestination(string(address))` on
every packet: a string allocation, `net.SplitHostPort` and `net.ParseAddress`,
three allocations in all.

IPv6 now takes the same path as IPv4:

- `parseIPv6UDPAddress` reads `[h:h::h]:port` from the message bytes into a
  `[16]byte`. It takes hexadecimal groups with at most one `::` and a decimal
  port of up to five digits. A dotted IPv4 tail (`::ffff:1.2.3.4`), a zone
  (`%eth0`), a longer port or anything else is left to `parseUDPDestination`
  as before. An IPv4-mapped result becomes an IPv4 destination, as
  `net.IPAddress` makes it.
- `buf.SetManagedUDPIPv6` stores the address in the buffer slab, next to the
  IPv4 field.

The routing destination of a session's first packet is built from the parsed
bytes and does not alias the slab.

The cost no longer depends on the previous packet's address. Hysteria 2.14.0
(apernet/hysteria `c2b181e0`) instead reuses the address string of the
previous UDP message, one per QUIC connection. An intermediate version of this
change cached the last four general addresses per session. It was faster on a
hit, but it missed on every packet once a session cycled through more than
four targets, and it was dropped (see below).

Guarded by `udp_reader_ipv6_test.go`:

- IPv6 literals, one repeated or sixteen in turn, allocate no more than an
  IPv4 literal on `ReadMultiBuffer` and `readFromPacket`;
- destinations match `parseUDPDestination`, IPv4-mapped hex included, across
  the IPv4, domain and IPv6 paths;
- the routing destination outlives the packet's metadata;
- a malformed address is skipped;
- `FuzzParseIPv6UDPAddressMatchesSlowParser` checks that every address the
  fast parser accepts parses to the same destination on the slow path (60 s,
  2.78 M executions, no mismatch).

`common/buf/writer_test.go` (`TestManagedUDPIPv6Metadata`) covers the slab
field and its reset on release.

### Conditions

- Go 1.27.3, linux/amd64, `GOFLAGS=-tags=http2legacy`.
- AMD Ryzen 7 5700X, 16 logical CPUs, WSL2 kernel 6.18.58.1, no cpufreq
  governor exposed. No builds or tests ran during the measurements.

### Reader microbenchmarks

Four variants of `proxy/hysteria/client.go`:

| Variant | Revision |
| --- | --- |
| Before | `7795bd6c` |
| Cache | `0449b536`, the four-entry cache |
| Parser and cache | parser, with the cache kept for the other addresses |
| Parser (adopted) | parser only |

Each variant was built with `go test -c ./proxy/hysteria`. Nine rounds ran
each variant once with:

```sh
"$binary" -test.run '^$' -test.benchtime 1s -test.count 1 -test.benchmem -test.cpu 1 \
  -test.bench '^Benchmark(UDPReaderReadMultiBuffer(IPv6|IPv6Small|Domain)?|UDPReaderReadMultiBufferIPv6Alternating|ZZManyIPv6|UDPReaderReadFrom(IPv6)?)$'
```

`ZZManyIPv6` was a throwaway copy of `BenchmarkUDPReaderReadMultiBufferManyIPv6`
that compiles against every variant. Medians in ns/op with the range, and
allocations per operation:

| Benchmark | Before | Cache | Parser and cache | Parser |
| --- | ---: | ---: | ---: | ---: |
| `ReadMultiBuffer` (IPv4) | 102.8 (102–133), 1 | 103.8 (101–106), 1 | 101.1 (100–103), 1 | 101.9 (100–103), 1 |
| `ReadMultiBufferDomain` | 94.4 (93–108), 1 | 96.0 (93–99), 1 | 97.9 (96–100), 1 | 92.7 (91–97), 1 |
| `ReadMultiBufferIPv6`, 1100 B | 177.2 (175–184), 3 | 89.4 (88–91), 1 | 129.8 (128–135), 1 | 130.7 (129–133), 1 |
| `ReadMultiBufferIPv6Small`, 64 B | 166.4 (166–212), 3 | 80.4 (79–85), 1 | 121.1 (121–125), 1 | 123.0 (122–127), 1 |
| `IPv6Alternating/targets=1` | 185.8 (184–190), 3 | 81.3 (80–86), 1 | 151.3 (150–154), 1 | 149.2 (146–151), 1 |
| `IPv6Alternating/targets=4` | 182.5 (180–218), 3 | 81.3 (80–84), 1 | 140.2 (139–143), 1 | 136.3 (135–139), 1 |
| `IPv6Alternating/targets=8` | 182.6 (181–193), 3 | 193.1 (187–203), 3 | 140.6 (140–143), 1 | 136.5 (136–140), 1 |
| `ManyIPv6`, 16 targets | 181.9 (181–194), 3 | 197.6 (195–202), 3 | 132.9 (132–135), 1 | 131.7 (130–135), 1 |
| `ReadFrom` (IPv4) | 83.8 (83–85), 2 | 85.6 (85–89), 2 | 84.6 (83–87), 2 | 85.7 (85–87), 2 |
| `ReadFromIPv6` | 157.0 (156–160), 3 | 73.0 (71–74), 1 | 130.8 (128–137), 2 | 131.3 (128–133), 2 |

The allocation left in `ReadMultiBuffer` is the packet's `buf.Buffer`, which
IPv4 pays too. `ReadFrom` has no production caller in the package; its second
allocation, like IPv4's, is the returned destination.

Parsing the IPv6 text costs 30–60 ns depending on its length. A cache hit is
cheaper, which makes the cache 55 ns faster per packet for one to four
targets. Past four targets the cache misses and costs 193–198 ns with three
allocations, while the parser stays at 132–140 ns. Kept behind the parser,
the cache never sees IPv6 and only adds code. The process measurements below
show the 55 ns as noise, so the parser alone was kept.

### Process level

`TestHysteriaUDPPerformanceAgainstBaseline` (`common/singmux/TESTING.md`)
runs a baseline and a candidate server behind the same candidate Xray
Hysteria client. The client sends 64-byte packets through one SOCKS UDP
association, at most 32 in flight, to UDP echoes. There were nine
alternating rounds of 200,000 packets after a full-size settling load, with
no losses. Server CPU time per packet, medians with the range, in ns:

| Targets | Before (`7795bd6c`) | Parser | Change |
| --- | ---: | ---: | ---: |
| IPv4 (control) | 32513 (32490–32825) | 32223 (32106–32590) | −0.9% |
| One IPv6 | 33519 (33348–33634) | 32761 (32647–32892) | −2.3% |
| Four IPv6 in turn | 32498 (32251–32943) | 31474 (31216–31562) | −3.2% |
| Sixteen IPv6 in turn | 32725 (32656–32915) | 31747 (31557–31936) | −3.0% |

| Targets | Cache (`912cf6d8`) | Parser | Change |
| --- | ---: | ---: | ---: |
| IPv4 (control) | 32582 (32464–32777) | 32374 (32132–32510) | −0.6% |
| One IPv6 | 33015 (32834–33279) | 32730 (32472–32847) | −0.9% |
| Four IPv6 in turn | 31814 (31712–32150) | 31502 (31263–31754) | −1.0% |
| Sixteen IPv6 in turn | 32784 (32527–32965) | 31528 (31363–31695) | −3.8% |

Server CPU per packet covers the whole round trip: QUIC, the upload reader,
the download writer, the runtime, and its idle spinning in this closed loop.

- Against the original reader, IPv6 gains 2–3% with non-overlapping ranges.
  That is more than the reader's ~50 ns: two fewer allocations per packet
  also mean less garbage collection, which this run does not separate.
- Against the cache, one or four targets differ by about 1%, with overlapping
  ranges. The candidate runs 0.6–0.9% below the baseline even on the
  unchanged IPv4 path, so the 55 ns microbenchmark difference does not show.
- Sixteen targets, where the cache misses, gain 3.8% with non-overlapping
  ranges.

Delivered pps moved within 1–3% in every mode, because the closed loop is
bounded by the whole path, client included.

### Limitations

- Addresses the parser does not take keep the old cost: a dotted IPv4 tail, a
  zone, a port with more than five digits.
- `TestHysteriaProcessClientMatrix` (plain/Gecko × Xray, sing-box, Mihomo)
  sends UDP to six IPv6 echoes per cell: one repeated, three in turn and all
  six in turn. It checks that each reply comes from its own target. A parser
  that swapped the bytes of each group failed all six cells.
- The process numbers come from WSL2 on a desktop CPU: a Linux kernel, but a
  virtualized one on a host that is not a server. They show the relative
  change; they are not server capacity figures.

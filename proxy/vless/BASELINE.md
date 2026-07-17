# VLESS behavior and performance baseline

Baseline ID: `vless-v0-behavior-2026-07-17`

This baseline fixes the observable behavior of the plain VLESS v0 TCP and Mux
paths before production optimization. XTLS/Vision, UDP framing, fallback
routing, and the optional VLESS encryption handshake remain outside this first
measurement and must retain their existing tests and process gates when a
shared code path changes.

## Source and conditions

- Xray commit: `8e3f90260e0887d12bef3b54d38fd18818fd2cfb` plus the
  characterization test in `encoding/behavior_test.go`.
- Host: darwin/arm64, Apple M3 Max, Go 1.26.5.
- Benchmark command:

  ```sh
  go test ./proxy/vless/encoding -run '^$' \
    -bench 'Benchmark(Encode|Decode)(Request|Response)Header' \
    -benchmem -benchtime=2s -count=5
  ```

## Frozen wire behavior

The deterministic user ID is `00112233-4455-6677-8899-aabbccddeeff`.

| Message | Hexadecimal wire representation |
| --- | --- |
| TCP to `example.com:443` | `0000112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d` |
| TCP to `192.0.2.1:443` | `0000112233445566778899aabbccddeeff000101bb01c0000201` |
| TCP to `[2001:db8::1]:443` | `0000112233445566778899aabbccddeeff000101bb0320010db8000000000000000000000001` |
| Mux command | `0000112233445566778899aabbccddeeff0003` |
| Empty response | `0000` |

The characterization suite also fixes these stream semantics:

- a valid header decoded from the inbound first buffer is not classified as a
  fallback;
- bytes received after that header remain available as the first payload;
- every split between byte 18 and the end of domain, IPv4, IPv6, and Mux
  headers falls back to the streaming decoder without losing payload bytes;
- plain TCP has no body framing or transformation;
- the outbound buffers the request header and waits up to 500 ms for an
  immediately available first payload before flushing;
- the inbound buffers the response header and flushes it with the first
  response payload.

## Header baseline

Medians of five runs:

| Operation | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Encode TCP/domain request | 113.2 | 172 | 6 |
| Decode TCP/domain request | 190.8 | 248 | 7 |
| Encode empty response | 51.66 | 104 | 2 |
| Decode empty response | 64.08 | 104 | 2 |

The request encoder allocation profile attributes almost all objects to
`EncodeRequestHeader`, address/port serialization, and returning the pooled
stack buffer. The decoder adds the returned request/addons objects, domain
construction, address parsing, and the same buffer return. The benchmark uses
a resettable `bytes.Reader`, so its reader does not contribute an allocation.

The existing shared domain-address benchmark records a 37.82 ns median, 20
B/op, and 3 allocs/op, accounting for half of the request encoder's allocation
count.

The inbound first-buffer A/B benchmark records:

| Variant | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Current unmanaged `make` | 915.8 | 8,240 | 2 |
| Owned pooled candidate | 40.38 | 72 | 2 |

The pooled candidate reduces allocated bytes by 99.1% and the isolated setup
time by about 95.6%. The object count is unchanged because both variants expose
the buffer object through the benchmark sink; the material difference is the
8 KiB backing store.

## Optimization worklist

1. **Inbound first buffer.** `inbound.Handler.Process` currently creates an
   unmanaged `buf.Size` byte slice for every accepted connection. Replacing it
   with an owned pooled buffer is the clearest connection-rate and GC target,
   provided fallback handoff and coalesced payload ownership stay unchanged.
2. **Plain header fast path.** Empty addons are the dominant VLESS/SMUX case.
   Encoding directly into caller-owned storage can avoid the temporary pooled
   buffer, interface escapes, and the second header copy while preserving the
   exact bytes above.
3. **Contiguous first-buffer decode.** The common path already has the whole
   header in the first read but parses it through several `io.Reader` calls.
   A bounded contiguous parser can reduce calls and temporary objects, with the
   fragmented-reader path retained as the fallback.
4. **Address serialization.** Domain encoding currently creates temporary
   byte slices for the type/length, port, and string conversion. Prefer a
   buffer-aware specialization; changing the shared protocol parser requires
   benchmarks for its other callers.
5. **Per-connection orchestration.** Contexts, activity timers, task closures,
   logging, and the two `buf.Copy` option closures are plausible setup costs.
   They require a process profile before modification.
6. **First-payload wait.** The 500 ms coalescing window trades a syscall for
   startup latency. It must be evaluated with both immediate-payload throughput
   and delayed/empty-payload latency, not changed from a throughput benchmark
   alone.

Header microbenchmarks characterize connection setup. Linux process-level
VLESS throughput and connection-rate tests remain the acceptance gate for any
production optimization.

## Optimized result

The first optimization pass keeps the frozen behavior above and changes only
the common plain-VLESS setup path:

- inbound first reads now use an owned pooled buffer, with explicit cleanup on
  pre-handoff errors and cleanup of any bytes left in `BufferedReader`;
- empty-addons request and response headers use a single exact-sized write;
- domain, IPv4, and IPv6 serialization is specialized in that plain fast path;
- complete plain headers in the first read use a contiguous decoder, while
  fragmented headers, non-empty addons, and unusual inputs keep the original
  streaming decoder.

Five-run medians after optimization:

| Operation | Baseline | Optimized | Allocated bytes | Allocations |
| --- | ---: | ---: | ---: | ---: |
| Encode TCP/domain request | 113.2 ns | 53.26 ns | 172 -> 128 | 6 -> 2 |
| Encode empty response | 51.66 ns | 30.35 ns | 104 -> 80 | 2 -> 1 |
| First-buffer setup | 677.7 ns | 62.49 ns | 8,240 -> 72 | 2 -> 2 |
| Contiguous TCP/domain decode | 334.9 ns | 209.6 ns | 416 -> 344 | 12 -> 10 |

The first-buffer decode row includes construction of the benchmark's
`BufferedReader`; the same harness is used on both sides. The streaming decode
benchmark is deliberately unchanged and remains the fragmentation control.

Linux/arm64 process gates use locally started Xray, sing-box, and mihomo
binaries:

- VLESS interoperability: 16/16 combinations passed (both peers, both Xray
  directions, TCP and UDP, padding off and on);
- VLESS server full-duplex ratios against sing-mux over three complete runs:
  `0.928`, `0.988`, and `0.938`, all below the `1.10` regression limit;
- reconnect/resource stress kept zero loopback error/drop/CRC/carrier deltas.
  One initial `mihomo` to Xray-server stream was reset; the isolated topology
  then passed five independent runs (15/15 cycles), so the reset is recorded
  as a non-reproduced process-test flake rather than hidden.

Worklist items 1-4 are complete. Items 5 and 6 remain deferred: the current
process measurements do not attribute meaningful cost to orchestration, and
changing the 500 ms first-payload coalescing window without a dedicated
connection-latency profile would alter behavior rather than perform a proven
optimization.

# Mux.Cool server baseline

Measurements of the Mux.Cool server worker (`common/mux`). SMUX has its own
baseline in `common/singmux/BASELINE.md`.

## Per-frame cost of the server worker (2026-10-10)

`BenchmarkServerWorkerKeepAliveFrames` (`server_performance_test.go`) feeds
one `ServerWorker` a stream of KeepAlive frames without payload; one op is one
frame. It isolates the frame loop: metadata parsing and dispatch by session
status, without a payload, a session or a dispatcher call.

### Conditions

- Before: `740205a2` (main), clean apart from the benchmark file copied from
  `a821b46a`.
- After: `a821b46a`, upstream v26.10.10 merged, which brings upstream's
  `PacketReader` fix (XTLS/Xray-core#6822).
- Go 1.27.2 linux/amd64, AMD Ryzen 9 9950X (32 threads), governor
  `powersave`, no other builds, tests or benchmarks running.
- Command, six samples on each side:

  ```sh
  GOFLAGS=-tags=http2legacy go test ./common/mux -run '^$' \
    -bench '^BenchmarkServerWorkerKeepAliveFrames$' -benchmem -count=6 -timeout 300s
  ```

### Results

| | median ns/op | range ns/op | B/op | allocs/op |
| --- | --- | --- | --- | --- |
| before | 61.15 | 59.65-63.10 | 98 | 3 |
| after | 52.96 | 52.61-53.41 | 50 | 2 |

The ranges do not overlap. `go build -gcflags=-m ./common/mux` explains the
difference. Before the fix, `PacketReader` kept a pointer to its caller's
destination and `ServerWorker.handleFrame` handed it `&meta.Target`, so
`meta` escaped (`server.go:535: moved to heap: meta`). The fix copies the
destination, so `meta` stays on the stack for every frame.

### Limits

- Only KeepAlive frames without payload were measured. A frame that carries
  data also pays for its payload buffer and session work, so its relative
  saving is smaller.
- The first frame of a new XUDP session now allocates its `PacketReader`
  (`server.go:398: &PacketReader{...} escapes to heap`). Before the fix it
  stayed on the stack.
- Both remaining allocations per op are on the server path, in
  `FrameMetadata.Unmarshal`. An allocation profile (`-memprofilerate=1`,
  `alloc_objects`) attributes 89 % of them to the `buf.New` header that holds
  the metadata bytes and 11 % to the length buffer of `serial.ReadUint16`.
- This is a microbenchmark of one primitive. Process-level Mux.Cool behavior
  is gated by `TestXHTTPMuxCoolProcess` and the XHTTP process gates, not by
  this number.

# SMUX release gates

The recorded reference point is in [`BASELINE.md`](BASELINE.md). YAMUX and
H2MUX are outside the scope of these gates; this suite is exclusively for the
in-tree SMUX v1 stack.

The default suite covers the wire codec, padding, pool behavior, TCP and UDP
adapters, Xray integration, the MPL SMUX engine, and the recursive external-mux
dependency ban. The engine package is held above 80% statement coverage.

```sh
go test ./common/singmux/... ./common/mux ./app/proxyman/outbound ./infra/conf
go test -race ./common/singmux/... ./common/mux
go test -cover ./common/singmux/internal/mplsmux
go test ./common/singmux/... -count=50
go test ./common/singmux/internal/mplsmux -run '^$' -bench '^BenchmarkStreamRoundTrip32KiB$' -benchmem -count=5
```

The 32 KiB hot-path allocation gate is four allocations per round trip and is
compiled only without `-race`, because race instrumentation changes allocation
behavior. Frame, padding, and outer-protocol decoders also have Go fuzz targets.

The functional process suite builds and starts Xray, sing-box, and Mihomo. It
runs both Xray client and Xray server directions for VLESS and Trojan, TCP and
UDP, with padding disabled and enabled (32 scenarios).

```sh
go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
```

The stress suite runs eight peer/direction/carrier topologies. Every topology
runs three cycles with 128 concurrent full-duplex TCP streams carrying 1 MiB in
each direction and 10,000 UDP datagrams across four destinations. The server is
killed and restarted between cycles while the client remains running.

```sh
go test -tags 'integration stress' ./common/singmux -run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
```

The hardening gate raises every topology to 50 cycles:

```sh
XRAY_SMUX_STRESS_CYCLES=50 go test -tags 'integration stress' ./common/singmux -run '^TestSMUXProcessStressAndReconnect$' -count=1 -v
```

On Linux, the stress test also captures a historical baseline and delta for the
loopback interface error, drop, CRC, carrier, collision, and carrier-change
counters. It never clears counters and fails if any checked counter increases.
Process RSS and thread counts are sampled after each cycle to detect linear
growth.

The performance suite compares the same Xray SMUX client against an Xray server
and the current local sing-box/sing-mux server. It uses a full-load warm-up and
nine alternating rounds with access logging disabled. The Linux VLESS result
enforces the 10% median full-duplex regression limit. The Trojan result is diagnostic
because it also compares the two projects' TLS and Trojan implementations.

```sh
go test -tags 'integration stress performance' ./common/singmux -run '^TestSMUXServerPerformanceAgainstSingMux$' -count=3 -v
```

`XRAY_E2E_BIN`, `SING_BOX_E2E_BIN`, and `MIHOMO_E2E_BIN` may point to existing
binaries. `XRAY_SMUX_STRESS_CYCLES` controls reconnect cycles.
`XRAY_SMUX_STRESS_TCP_STREAMS` may reduce TCP concurrency for a diagnostic run;
the release gate must run without the TCP override.

The production path contains no vendored SMUX/YAMUX/H2MUX implementation and
does not import Sagernet, Metacubex, Hashicorp, or another mux library. The
embedded SMUX engine is maintained in this tree under MPL-2.0.

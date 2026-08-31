# MTProxy baseline

## Secret-probe capacity baseline

Command:

    GOTOOLCHAIN=auto go test ./proxy/mtproxy -run '^$' \
      -bench '^BenchmarkSecretProbe' -benchtime=1x -count=1

Conditions:

- revision before benchmark commit: 9f8de3e53621cfcce49df5292f7c30c169d116b1
- working tree: dirty with the benchmark and hardening changes under measurement
- Go: go1.27.0 linux/amd64
- host: Linux 7.1.9-200.fc44.x86_64, amd64
- CPU: AMD Ryzen 7 4800H with Radeon Graphics
- each row is one worst-case invalid 64-byte handshake

| candidate secrets | time/op | bytes/op | allocs/op |
|---:|---:|---:|---:|
| 1 | 2.264 us | 560 | 4 |
| 4 | 3.326 us | 2,240 | 16 |
| 8 | 5.120 us | 4,480 | 32 |
| 16 | 7.444 us | 8,976 | 65 |
| 32 | 26.450 us | 17,920 | 128 |
| 64 | 32.541 us | 35,840 | 256 |
| 128 | 70.624 us | 71,696 | 513 |
| 256 | 150.875 us | 143,360 | 1,024 |
| 1,000 | 491.328 us | 560,000 | 4,000 |
| 10,000 | 5.001 ms | 5,600,000 | 40,000 |
| 100,000 | 37.479 ms | 56,005,992 | 400,015 |
| 500,000 | 213.860 ms | 280,000,336 | 2,000,003 |

Decision: the supported hard limit is 16 client secrets per inbound, matching
the reference implementation. Five hundred thousand candidates are retained in
the benchmark as negative capacity evidence, not a supported operating mode.
The protocol carries no secret identifier, so invalid DD handshakes necessarily
perform linear multi-key work. At 500,000 candidates one invalid connection
already consumes about 214 ms and 280 MB of allocation on this host.

Limitations: one-shot figures include benchmark noise and are not throughput or
DoS-capacity claims. Release decisions must rerun the matrix on the target Linux
server and add process-level invalid-handshake load measurements.

# Structured Logging Design

Status: implemented; legacy `Message`/`Handler` compatibility remains

This document defines the target logging architecture for the Xray server. It
is intentionally implementation-independent: tests exercise the interfaces
and observable behavior described here, while queue, buffer, and encoder
implementations may change after profiling.

## Goals

- Represent general, access, DNS, and logger-internal records as structured
  events rather than preformatted strings.
- Emit deterministic JSON Lines to files and Unix stream sockets.
- Emit compact, optionally colored, human-readable records to a console.
- Keep the data plane non-blocking by default and make every dropped record
  observable.
- Preserve record ordering within each output.
- Flush accepted records during bounded shutdown.
- Avoid shared mutable records, unbounded queues, recursive error logging, and
  per-record goroutines.
- Preserve the existing JSON and protobuf logging configuration when the new
  output list is absent.
- Preserve disabled-log and dispatch hot-path allocation budgets.

The Linux/amd64 Xray server is the runtime and performance target. Darwin
benchmarks are development evidence only.

## Non-goals

- The core does not rotate or compress log files. Operators should keep using
  `s6-log`, `logrotate`, or their collector for retention.
- The core does not send logs over an Internet-facing TCP or UDP protocol.
  The socket output is a local Unix stream client intended for a local
  collector.
- Logging must not change VLESS, Trojan, REALITY, Vision, or SMUX wire bytes.
- The design does not introduce a third-party logging dependency.

## Module and seams

The logging module is a deep module with one call-site interface:

```go
Enabled(kind Kind, severity Severity) bool
Emit(event Event)
```

`Event` is an owned snapshot when `Emit` returns. A caller may reuse or mutate
its source objects without changing an accepted event. Existing
`Record(Message)`, `Message`, `Handler`, and `errors.Log*` entry points remain
as compatibility adapters during migration.

The module has two internal seams that are real because each has multiple
adapters:

```go
type Encoder interface {
    Append(dst []byte, event Event) []byte
}

type Output interface {
    WriteBatch(records [][]byte) error
    Flush() error
    Close() error
}
```

The encoder adapters are JSON Lines and console text. The output adapters are
console, append-only file, and Unix stream socket. These internal seams are not
exposed to protocol call sites.

The behavior is tested at five agreed surfaces:

1. `Emit`/`Enabled`: filtering, snapshot ownership, ordering, overflow
   accounting, and concurrent lifecycle.
2. Encoder output: exact deterministic JSON and console records.
3. Real output behavior: `os.Pipe`, a temporary file, and a real temporary
   Unix listener; internal collaborators are not mocked.
4. Configuration build: legacy translation and explicit output validation.
5. Process behavior: a real Xray process and mandatory proxy clients produce
   parseable records for successful and rejected connections.

## Event model

Every event has common fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | integer | JSON schema version; initially `1` |
| `timestamp` | RFC3339Nano UTC string | Time accepted by the logger |
| `type` | string | `general`, `access`, `dns`, or `internal` |
| `level` | string | `error`, `warning`, `info`, or `debug` |
| `component` | string | Stable Xray subsystem name |
| `message` | string | Human-readable summary, if applicable |
| `session_id` | unsigned integer | Optional Xray connection/session ID |

Access events add fixed fields rather than an arbitrary map:

- `source`
- `destination`
- `network`
- `status`
- `inbound`
- `outbound`
- `email`
- `reason`

DNS events add:

- `server`
- `domain`
- `answers`
- `status`
- `elapsed_ms`
- `error`

Fields with no value are omitted. Field order is stable and defined by the
encoder, so golden records and downstream parsers do not depend on Go map
iteration. Strings are valid UTF-8 in the output; invalid input bytes are
replaced during encoding. JSON records always end in exactly one newline.

An access context contains only connection metadata that is valid for all
derived streams. The dispatcher finalizes a new access event with the actual
stream destination and selected outbound. It never mutates an access event in
the parent context. This is required for SMUX, where concurrent logical
streams share one carrier context.

Example access record:

```json
{"schema":1,"timestamp":"2026-07-18T18:00:00.123456789Z","type":"access","level":"info","source":"tcp:192.0.2.10:51000","destination":"tcp:100.85.127.181:80","network":"tcp","status":"accepted","inbound":"DE 1 Vless Reality","outbound":"DIRECT","email":"user@example.com"}
```

## Console format and color

Console output is a formatter, not a separate event model. Its stable logical
layout is:

```text
2026-07-18T18:00:00.123Z INFO  access app/dispatcher source=tcp:192.0.2.10:51000 destination=tcp:100.85.127.181:80 inbound="DE 1 Vless Reality" outbound=DIRECT status=accepted
```

Color modes are `auto`, `always`, and `never`:

- `auto` enables ANSI color only for a character-device console and honors
  `NO_COLOR`.
- `always` is intended for an explicitly ANSI-aware consumer.
- `never` guarantees byte-clean output for redirection and tests.

Only the level and event-type labels are colored. User-controlled values are
quoted and never interpreted as ANSI control sequences.

## Pipeline and concurrency ownership

The global call-site router publishes one immutable runtime snapshot through
an atomic pointer. `Enabled` and disabled events take no mutex.

Each configured output owns exactly one bounded queue and one worker. That
worker exclusively owns its encoder scratch buffer, batch, `bufio.Writer`,
file descriptor or Unix connection, flush timer, and reconnect state. There
is no goroutine per event, packet, or reconnect attempt.

An accepted event is copied by value into every matching output queue. Any
variable-length field storage is copied once before `Emit` returns. Workers
may therefore encode the same event concurrently without a data race.

Ordering is defined per output: if output A accepts event 1 before event 2,
A writes event 1 before event 2. Ordering between different outputs is not
defined.

## Backpressure

Every output has a bounded queue and one explicit policy:

- `drop_new`: do not block the data plane; reject the new event when full.
- `block`: wait until queue capacity is available or the configured timeout
  expires.
- `sync`: bypass the queue and serialize every event directly through the
  output lock.

The default is `drop_new`, preserving non-blocking server behavior. Unlike the
old implementation, loss is never silent. Each output publishes monotonic
`accepted`, `written`, `dropped`, `write_errors`, `reconnects`, and
`queue_depth` counters. A rate-limited emergency record is written directly
to stderr when the dropped or write-error count changes. Emergency reporting
must not call back into the logging module.

`block` is opt-in because a failed disk or collector must not unexpectedly
stall proxy traffic. `sync` is intended for low-volume audit/error outputs and
is not the default access-log policy.

Queue size, maximum batch size, flush interval, block timeout, and maximum
encoded record size are bounded configuration values. Oversized records are
truncated at a valid UTF-8 boundary and include `truncated:true`; the encoder
must not allocate in proportion to an untrusted declared size.

## Output lifecycle

### Console

The console worker writes complete batches to stdout or stderr. It never
closes process-owned standard streams.

### File

The file worker opens an append-only file once at start, with mode `0600` for
a newly created file, and keeps ownership until restart or close. It uses a
buffered writer and flushes on batch size, flush interval, explicit restart,
and close. Open, write, flush, and close errors update counters and reach the
emergency reporter.

The existing logger restart RPC performs a bounded drain and atomically
publishes a new runtime only after every new output has opened successfully.
Failure leaves the previous runtime active.

### Unix socket

The socket worker connects to an existing Unix stream socket. Each payload is
JSON Lines, so a collector can parse records incrementally. Connect and write
operations have deadlines. After a broken connection, the next batch makes
one bounded reconnect attempt. There is no background retry goroutine and a
possibly partially written batch is not replayed, because replay could create
duplicate audit records. Failed batches increment `write_errors`.

## Shutdown and reload

The lifecycle states are `new`, `running`, `draining`, and `closed`.

- `Start` validates all configuration and opens all required outputs before
  publishing the runtime.
- `Close(ctx)` stops accepting new events, drains accepted events, flushes and
  closes outputs, and returns either completion or the caller deadline.
- Calls racing with close are safe and are either accepted before the drain
  barrier or rejected and counted; they never panic or write through a closed
  channel.
- Reload constructs a complete replacement runtime first, atomically swaps it
  into the global router, then drains the old runtime.

## Configuration

For deployable JSON examples, migration guidance, field reference, rotation,
and operational troubleshooting, see [`CONFIGURATION.md`](CONFIGURATION.md).

The protobuf retains fields 1 through 7 unchanged. A repeated explicit output
list is added with new field numbers. An output selects event types, severity,
destination, encoder, color mode, batching, and backpressure.

Conceptual JSON:

```json
{
  "log": {
    "loglevel": "warning",
    "outputs": [
      {
        "name": "console",
        "type": "console",
        "stream": "stderr",
        "events": ["general", "internal"],
        "format": "console",
        "color": "auto"
      },
      {
        "name": "access-file",
        "type": "file",
        "path": "/var/log/remnanode/access.jsonl",
        "events": ["access", "dns"],
        "format": "json",
        "queueSize": 4096,
        "batchSize": 64,
        "flushInterval": "250ms",
        "backpressure": "drop_new"
      },
      {
        "name": "collector",
        "type": "unix",
        "path": "/run/remnanode/log.sock",
        "events": ["general", "access", "dns", "internal"],
        "format": "json"
      }
    ]
  }
}
```

When `outputs` is absent, legacy fields are translated as follows:

- `access: "none"` produces no access/DNS output.
- empty `access` produces a console access/DNS output.
- a non-empty access path produces an append-only text file output during the
  compatibility phase.
- `error: "none"` produces no general output.
- empty `error` produces a console general output.
- a non-empty error path produces an append-only text file output.
- `loglevel`, `dnsLog`, and `maskAddress` retain their current meaning.

Explicit outputs use structured JSON for file and socket destinations by
default. Legacy text output remains available until a separately documented
configuration migration removes it.

Invalid output names, duplicate names, shared file/socket destinations, empty
paths, unsupported encoder/output combinations, and excessive bounds fail
before any destination is opened. Zero-valued
runtime fields select defaults. Runtime bounds per output are:

- queue: default 1024 events, maximum 65536;
- batch: default 32 events, maximum 4096;
- encoded record: default 64 KiB, range 1 KiB through 16 MiB;
- maximum queue-size × record-size budget: 256 MiB;
- maximum batch-size × record-size budget: 64 MiB;
- flush interval: default one second;
- new file mode: `0600`, default userspace buffer 64 KiB;
- Unix connect/write timeout: default five seconds at the application layer.

## Privacy and safety

Address masking is applied to typed address fields before either encoder runs;
the implementation must not regex-rewrite serialized JSON. Legacy general
message masking remains in its compatibility adapter. Log values may contain
untrusted domains, emails, reasons, and errors, so encoders escape control
characters and console ANSI sequences.

The logger never records private keys, REALITY keys, UUIDs, passwords, or raw
payload bytes merely because structured output is enabled. Call sites remain
responsible for not attaching secrets.

## Performance contracts

The initial legacy Darwin/arm64 baseline at revision
`e2ed8329ce2a357186fb521d3f1bf28f3b13d471` with Go 1.26.5 is:

| Benchmark | Median | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkRecord` | 2.01 ns/op | 0 | 0 |
| `BenchmarkAccessMessageString` | 43.04 ns/op | 112 | 1 |
| `BenchmarkAcceptedTypedAccessMessageString` | 36.68 ns/op | 96 | 1 |
| `BenchmarkWriteLogMessage` | 37.94 ns/op | 32 | 1 |

Required contracts:

- disabled general logging: zero allocations;
- global enabled/filter check: zero allocations and no mutex;
- event enqueue with only fixed fields: zero steady-state allocations;
- JSON and console encoding into caller-provided capacity: zero steady-state
  allocations;
- memory use bounded by configured queues, batches, and maximum record size;
- no throughput or tail-latency regression outside the documented budget for
  VLESS TCP TLS/REALITY flow and no-flow server tests.

Final performance claims require at least five comparable samples on
Linux/amd64, allocation counts, queue saturation tests, RSS/GC/goroutine/FD
measurements, and network-interface/TCP counters.

The current implementation measurements and exact commands are recorded in
[`BASELINE.md`](BASELINE.md). Linux/arm64 runtime results are development
evidence; the Linux/amd64 performance gate remains intentionally separate from
the successful Linux/amd64 release cross-build.

## Acceptance gates

- Exact encoder golden tests, escaping tests, and independent JSON parsing.
- Concurrent emit, filter, reload, overflow, write failure, and close tests
  under `-race`.
- Allocation budgets and serial/parallel benchmarks for filtering, enqueue,
  JSON, console, file batching, and Unix socket batching.
- Bounded-memory saturation test with a stalled output.
- Real temporary-file and Unix-listener lifecycle tests, including reconnect.
- Logger restart test proving failed replacement preserves the old runtime.
- Process test proving successful and rejected Xray connections produce the
  expected structured fields.
- Mandatory Xray, sing-box, and Mihomo VLESS/Trojan compatibility cells for
  paths whose call sites change.
- Repository tests, vet, Linux/amd64 release build, and the server/network
  gates documented by the repository development instructions.

## Implementation and remaining migration

Implemented: owned typed events, deterministic encoders, bounded workers,
console/file/Unix outputs, counters, emergency reporting, atomic reload,
protobuf/JSON configuration, typed DNS statuses, typed route metadata, and
independent per-stream SMUX access records. The compatibility adapter is still
used by historical call sites.

Remaining migration: convert historical general/access/DNS producers to emit
typed events directly, then remove the compatibility implementation only
after every in-tree call site and external configuration gate uses the new
module. Keep legacy configuration translation until an explicitly versioned
removal.

# Structured Logging Configuration

This guide describes the explicit structured logging configuration used by
this fork. For the implementation model and concurrency guarantees, see
[`DESIGN.md`](DESIGN.md). For performance baselines, see
[`BASELINE.md`](BASELINE.md).

## Migration from legacy logging

Legacy logging remains compatible:

```json
{
  "log": {
    "error": "/var/log/remnanode/access.log",
    "access": "/var/log/remnanode/access.log",
    "loglevel": "warning"
  }
}
```

When `log.outputs` contains at least one item, the structured runtime replaces
the legacy access and error handlers. Remove `access`, `error`, and `dnsLog`
from the configuration to avoid ambiguity. `loglevel` remains the default
level for outputs that do not set `level`; `maskAddress` continues to apply to
typed address fields.

Access and successful DNS events have level `info`. An output that accepts
`access` or `dns` should normally set `"level": "info"`; the default
`warning` level filters those events out.

## Recommended RemnaNode configuration

The following configuration writes warnings and internal failures to the
console and writes all event families as JSON Lines to one file:

```json
{
  "log": {
    "loglevel": "warning",
    "maskAddress": "",
    "outputs": [
      {
        "name": "console",
        "type": "console",
        "stream": "stderr",
        "events": ["general", "internal"],
        "format": "console",
        "color": "auto",
        "level": "warning",
        "queueSize": 256,
        "batchSize": 16,
        "flushInterval": "250ms",
        "backpressure": "drop_new",
        "maxRecordSize": 65536
      },
      {
        "name": "json-file",
        "type": "file",
        "path": "/var/log/remnanode/xray.jsonl",
        "events": ["general", "access", "dns", "internal"],
        "format": "json",
        "level": "info",
        "queueSize": 4096,
        "batchSize": 64,
        "flushInterval": "250ms",
        "backpressure": "drop_new",
        "maxRecordSize": 16384,
        "fileBufferSize": 262144
      }
    ]
  }
}
```

The directory must already exist and be writable by the Xray process. A new
file is created with mode `0600`. Existing files are opened in append mode.

The file contains one JSON object per line. For example:

```json
{"schema":1,"timestamp":"2026-07-18T18:00:00.123456789Z","type":"access","level":"info","source":"tcp:192.0.2.10:51000","destination":"tcp:100.85.127.181:80","network":"tcp","status":"accepted","inbound":"DE 1 Vless Reality","outbound":"DIRECT","email":"user@example.com"}
```

## Console-only configuration

Use console-only output when `s6-log`, journald, or the container runtime owns
storage and rotation:

```json
{
  "log": {
    "outputs": [
      {
        "name": "console",
        "type": "console",
        "stream": "stderr",
        "events": ["general", "access", "dns", "internal"],
        "format": "console",
        "color": "auto",
        "level": "info",
        "queueSize": 1024,
        "batchSize": 32,
        "flushInterval": "250ms",
        "backpressure": "drop_new"
      }
    ]
  }
}
```

`color` accepts:

- `auto`: enable ANSI colors only when the selected stream is a terminal and
  `NO_COLOR` is not set;
- `always`: always emit ANSI colors;
- `never`: never emit ANSI colors.

Container stdout and stderr are normally pipes, so `auto` intentionally emits
plain text. Use `always` only when every downstream consumer handles ANSI
escape sequences.

## Unix stream collector

An output can send JSON Lines to a local Unix stream collector such as Vector
or Fluent Bit:

```json
{
  "log": {
    "outputs": [
      {
        "name": "collector",
        "type": "unix",
        "path": "/run/remnanode/xray-log.sock",
        "events": ["general", "access", "dns", "internal"],
        "format": "json",
        "level": "info",
        "queueSize": 4096,
        "batchSize": 64,
        "flushInterval": "250ms",
        "backpressure": "drop_new",
        "connectTimeout": "2s",
        "maxRecordSize": 16384
      }
    ]
  }
}
```

`socket` is accepted as an alias for `unix`. The listener must exist before
Xray starts. Initial connection failure rejects the configuration. After a
broken connection, the next batch performs one bounded reconnect attempt;
failed or partially written batches are not replayed.

## Output fields

| Field | Values and behavior |
| --- | --- |
| `name` | Required unique output name. |
| `type` | `console`, `file`, `unix`, or the `socket` alias. |
| `path` | Required for file and Unix outputs. |
| `stream` | `stdout` or `stderr`; console only, default `stdout`. |
| `events` | Any unique subset of `general`, `access`, `dns`, `internal`; empty selects all. |
| `format` | `console`/`text` or `json`/`jsonl`; file and Unix outputs require JSON. |
| `color` | `auto`, `always`, or `never`; meaningful for console format only. |
| `level` | `error`, `warning`/`warn`, `info`, or `debug`. |
| `queueSize` | Bounded per-output event queue. |
| `batchSize` | Maximum records written together by the output worker. |
| `flushInterval` | Maximum buffered-file flush interval, for example `250ms` or `1s`. |
| `backpressure` | `drop_new`, `block`, or `sync`. |
| `blockTimeout` | Maximum wait when `backpressure` is `block`. |
| `maxRecordSize` | Maximum encoded record size; oversized records are safely truncated. |
| `fileBufferSize` | Userspace file buffer size in bytes. |
| `connectTimeout` | Unix socket connect and write timeout. |

Output names must be unique. Two file outputs cannot share the same file, and
two Unix outputs cannot share the same socket path. Configuration errors are
reported before the new runtime is published.

## Backpressure and memory

Each output has one bounded queue and one worker. There is no goroutine per
event.

- `drop_new` is the server-safe default. A full or stalled output does not
  block proxy traffic. Dropped records are counted and reported by a
  rate-limited emergency message on stderr.
- `block` waits for queue capacity up to `blockTimeout`. Use it only when log
  completeness is more important than data-plane latency.
- `sync` bypasses the queue and serializes the caller on output I/O. Reserve it
  for low-volume audit or error streams.

Zero values select these defaults:

| Setting | Default | Limit |
| --- | ---: | ---: |
| Queue | 1024 records | 65536 records |
| Batch | 32 records | 4096 records |
| Maximum record | 64 KiB | 1 KiB through 16 MiB |
| Flush interval | 1 second | must not be negative |
| Block timeout | 1 second | must not be negative |
| File buffer | 64 KiB | 16 MiB |
| Unix timeout | 5 seconds | must not be negative |

The configured queue-size times maximum-record-size budget cannot exceed
256 MiB per output. The batch-size times maximum-record-size budget cannot
exceed 64 MiB. These are validation ceilings, not preallocated memory.

## JSON schema

Every JSON record contains `schema`, `timestamp`, `type`, and `level`. Optional
common fields are `component`, `message`, and `session_id`.

Access records may contain `source`, `destination`, `network`, `status`,
`inbound`, `outbound`, `email`, and `reason`. DNS records may contain `server`,
`domain`, `answers`, `status`, `elapsed_ms`, and `error`. Empty fields are
omitted, field order is deterministic, and every record ends with one newline.

## Rotation and lifecycle

Xray does not rotate or compress direct file outputs. Use one of these models:

1. Prefer console output and let `s6-log`, journald, or the container runtime
   own rotation.
2. Use `logrotate` with `copytruncate` for a direct file when a small race
   window is acceptable.
3. Rename/create files and invoke the logger restart RPC or restart Xray so the
   held file descriptor is reopened.

A logger restart constructs and opens the complete replacement runtime before
publishing it. If validation or opening an output fails, the old runtime stays
active. A successful restart drains accepted records, flushes buffers, and
closes the old outputs.

## Validation and inspection

Validate the complete Xray configuration before deployment:

```sh
xray run -test -config /path/to/config.json
```

Inspect JSON Lines without treating them as plain text:

```sh
tail -f /var/log/remnanode/xray.jsonl | jq -c .
```

For console output managed by the current RemnaNode image, inspect the s6 log:

```sh
docker exec remnanode tail -f /var/log/xray/current
```

Emergency messages on stderr include the output name and report queue drops,
write errors, or reconnect failures. They deliberately bypass the structured
runtime so a failed logging destination cannot hide its own failure.

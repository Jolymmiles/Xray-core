#!/usr/bin/env python3
"""A download through the tunnel while other traffic fills the link's queue.

An Xray client and server stand on the link of stand.py, 60 Mbit/s and a
round trip of 144 ms unless given, with a queue of --queue-bdp
bandwidth-delay products. Each run starts both and reads one download through
the tunnel for --duration seconds. --burst-at seconds in, --flows plain TCP
downloads from the server's namespace to the client's start beside it, past
Xray, and run for --burst seconds: traffic that is not the server's and
keeps the queue full, as on a link shared in the evening.

It needs what stand.py needs:

  go build -o origin ./testing/xhttpflow/slowreader/origin
  sudo python3 testing/xhttpflow/slowreader/burst.py \\
      --origin ./origin --client /path/to/xray-client \\
      --server stock=/path/to/xray --h2flow 'stock={"enabled": false}' \\
      --server before=/path/to/xray-before --server after=/path/to/xray-after \\
      --runs 3

--client-h2flow '{"enabled": true}' turns the governor on in the client as
well, which needs a client built with it: a bridge's downloads are its own.

Every --server build runs --runs times, all runs shuffled together. The
download's rate is sampled every half second. The table gives the rate
before the burst, the mean over the burst and over its second half, the
lowest half second of the burst, and the seconds after it until two samples
in a row are back at four fifths of the rate before: median, least and
most. A governor that cuts against a queue it does not make takes the
download towards nothing; one without a governor keeps a share of the link.

A run is valid if the tunnel came up, the download read through the whole
run, and every outside flow connected. Invalid runs are reported and left
out, and a single one makes the stand exit with status 1.
"""

import argparse
import contextlib
import json
import os
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

import stand

SAMPLE = 0.5
OUTSIDE_PORT = 9000

# The outside sender: in the server's namespace, it writes zeros to every
# connection it accepts until the connection goes.
SENDER = f"""
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.9.0.1", {OUTSIDE_PORT}))
s.listen(64)
block = bytes(1 << 16)
def feed(c):
    try:
        while True:
            c.sendall(block)
    except OSError:
        pass
while True:
    c, _ = s.accept()
    threading.Thread(target=feed, args=(c,), daemon=True).start()
"""


def outside(n, seconds, connected, addr=("10.9.0.1", OUTSIDE_PORT)):
    """Reads n plain TCP downloads from the outside sender for seconds, and
    adds to connected, for each, the bytes it read, how long it read and how
    it ended: None when it read to its deadline, otherwise the error. A run
    counts only with every flow read to its deadline."""
    def read():
        start, got = time.time(), 0
        try:
            s = socket.create_connection(addr, timeout=5)
        except OSError as e:
            connected.append((0, 0.0, f"connect: {e}"))
            return
        end = time.time() + seconds
        err = None
        try:
            while time.time() < end:
                s.settimeout(max(0.05, end - time.time()))
                try:
                    n = len(s.recv(1 << 16))
                except socket.timeout:
                    continue
                if not n:
                    err = "closed before its deadline"
                    break
                got += n
        except OSError as e:
            err = str(e)
        finally:
            s.close()
        connected.append((got, time.time() - start, err))
    threads = [threading.Thread(target=read) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def take_header(head, chunk):
    """Adds chunk to the response header read so far. The header may come in
    pieces, and only what follows its end is body: it returns the header so
    far and no body until the end has come, then None and the body bytes of
    chunk. A status other than 200, or no end in 64 KiB, is an OSError."""
    head += chunk
    cut = head.find(b"\r\n\r\n")
    if cut < 0:
        if len(head) > 1 << 16:
            raise OSError("no end of the header")
        return head, 0
    if not head.startswith(b"HTTP/1.1 200"):
        raise OSError(f"status {head[:12]!r}")
    return None, len(head) - cut - 4


def one_run(server_binary, args, name):
    with contextlib.ExitStack() as stack:
        server, client = stand.start_xray(stack, server_binary, args, name)
        ready_by = time.time() + stand.READY_TIMEOUT
        while stand.ping(2) is None:
            if time.time() > ready_by or server.poll() is not None or client.poll() is not None:
                return {"invalid": "the tunnel did not come up"}
            time.sleep(0.2)
        sender = subprocess.Popen(["ip", "netns", "exec", args.srv_ns, sys.executable, "-c", SENDER],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stand.reap, sender)
        got = [0]
        lock = threading.Lock()
        end = time.time() + args.duration
        result = {}

        def count():
            # stand.download keeps its count to itself, so this reads the
            # download here, the same way.
            try:
                s = stand.socks(time.time() + stand.PING_TIMEOUT)
            except OSError as e:
                result["error"] = f"no session: {e}"
                return
            try:
                s.settimeout(stand.time_left(end))
                s.sendall(b"GET /down?bytes=%d HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n"
                          % stand.DOWNLOAD_BYTES)
                buf = memoryview(bytearray(1 << 20))
                head = b""
                while time.time() < end:
                    s.settimeout(max(0.05, end - time.time()))
                    try:
                        n = s.recv_into(buf)
                    except socket.timeout:
                        break
                    if not n:
                        raise OSError("closed early")
                    if head is not None:
                        head, n = take_header(head, bytes(buf[:n]))
                    with lock:
                        got[0] += n
            except OSError as e:
                result["error"] = str(e)
            finally:
                s.close()

        reader = threading.Thread(target=count)
        reader.start()
        connected = []
        flows = threading.Timer(args.burst_at, outside, (args.flows, args.burst, connected))
        flows.start()
        samples, last = [], 0
        start = time.time()
        while time.time() < end:
            time.sleep(max(0, start + (len(samples) + 1) * SAMPLE - time.time()))
            with lock:
                cur = got[0]
            samples.append(round((cur - last) * 8 / SAMPLE / 1e6, 2))
            last = cur
        reader.join()
        flows.join()
        if "error" in result:
            return {"invalid": f"the download failed: {result['error']}", "samples": samples}
        bad = [c for c in connected if c[2] is not None]
        if len(connected) != args.flows or bad:
            return {"invalid": f"{len(connected) - len(bad)} of {args.flows} outside flows read to their deadline ({bad[0][2] if bad else 'missing'})",
                    "samples": samples, "flows": connected}
        return {"samples": samples, "flows": connected}


def summary(samples, args):
    """What the table shows of one run."""
    at, burst = int(args.burst_at / SAMPLE), int(args.burst / SAMPLE)
    before = statistics.median(samples[max(0, at - 8):at])
    during = samples[at:at + burst]
    back = None
    for i in range(at + burst, len(samples) - 1):
        if samples[i] >= 0.8 * before and samples[i + 1] >= 0.8 * before:
            back = (i - at - burst) * SAMPLE
            break
    return {"before": before, "mean": statistics.mean(during), "late": statistics.mean(during[len(during) // 2:]),
            "low": min(during), "back": back}


def inside(args):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    servers = dict(s.split("=", 1) for s in args.server)
    results = {name: [] for name in servers}
    invalid = {name: 0 for name in servers}
    jobs = [name for name in servers for _ in range(args.runs)]
    random.shuffle(jobs)
    with open(args.out, "a") as out:
        for i, name in enumerate(jobs, 1):
            try:
                r = one_run(servers[name], args, name)
            except BaseException:
                stand.show_xray_logs(args.work)
                raise
            out.write(json.dumps({"server": name, "flows": args.flows, "burst": args.burst, **r}) + "\n")
            out.flush()
            if "invalid" in r:
                invalid[name] += 1
                print(f"[{i}/{len(jobs)}] {name}: INVALID, {r['invalid']}", flush=True)
                stand.show_xray_logs(args.work)
                continue
            s = summary(r["samples"], args)
            results[name].append(s)
            print(f"[{i}/{len(jobs)}] {name}: before {s['before']:.1f}, burst mean {s['mean']:.1f}, "
                  f"lowest {s['low']:.1f} Mbit/s, back after {s['back']} s", flush=True)

    print("\n| | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))

    def spread(rs, key, unit):
        values = [r[key] for r in rs]
        if any(v is None for v in values):
            return f"{sum(v is None for v in values)} of {len(values)} not back"
        return f"{statistics.median(values):.1f} ({min(values):.1f}-{max(values):.1f}){unit}"

    rows = [
        ("Valid runs", lambda n, rs: f"{len(rs)} of {len(rs) + invalid[n]}"),
        ("Before the burst, Mbit/s", lambda n, rs: spread(rs, "before", "")),
        ("Mean over the burst, Mbit/s", lambda n, rs: spread(rs, "mean", "")),
        ("Mean over its second half, Mbit/s", lambda n, rs: spread(rs, "late", "")),
        ("Lowest half second of it, Mbit/s", lambda n, rs: spread(rs, "low", "")),
        ("Back at 4/5 of the rate before, after the burst", lambda n, rs: spread(rs, "back", " s")),
    ]
    for label, f in rows:
        print(f"| {label} | " + " | ".join(f(n, rs) if rs else "-" for n, rs in results.items()) + " |")
    failed = sum(invalid.values())
    if failed:
        print(f"\n{failed} of {len(jobs)} runs were invalid: the comparison is incomplete", file=sys.stderr)
    return 1 if failed or not all(results.values()) else 0


def outer(args):
    if os.geteuid() != 0:
        sys.exit("needs root: it creates network namespaces")
    servers = dict(s.split("=", 1) for s in args.server)
    h2flow = {name: json.loads(value) for name, value in (s.split("=", 1) for s in args.h2flow or [])}
    if set(h2flow) - set(servers):
        sys.exit(f"--h2flow names no --server: {', '.join(sorted(set(h2flow) - set(servers)))}")
    if args.burst_at + args.burst + 2 > args.duration:
        sys.exit("--duration must leave time after the burst")
    srv, cli = f"xburst-{os.getpid()}-srv", f"xburst-{os.getpid()}-cli"
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    code = None
    with contextlib.ExitStack() as stack:
        work = tempfile.mkdtemp(prefix="burst-")
        stack.callback(shutil.rmtree, work, ignore_errors=True)
        origin_log = stack.enter_context(open(f"{work}/origin.log", "w+b"))

        def show_origin_log(exc_type, exc, tb):
            if code != 0 or exc_type is not None:
                stand.show_log("origin", origin_log)

        stack.push(show_origin_log)
        stand.setup_network(stack, srv, cli, args.mbit, args.rtt, 0, args.server_cc, args.queue_bdp)
        private_key, public_key = stand.reality_keys(next(iter(servers.values())))
        stand.XMUX["maxConnections"] = args.connections
        for name in servers:
            with open(f"{work}/server-{name}.json", "w") as f:
                json.dump(stand.server_config(private_key, h2flow.get(name)), f)
        with open(f"{work}/client.json", "w") as f:
            json.dump(stand.client_config(public_key, json.loads(args.client_h2flow) if args.client_h2flow else None), f)
        origin = subprocess.Popen(["ip", "netns", "exec", srv, args.origin],
                                  stdout=subprocess.DEVNULL, stderr=origin_log)
        stack.callback(stand.reap, origin)
        measure = subprocess.Popen(["ip", "netns", "exec", cli, sys.executable, os.path.abspath(__file__), "--inside",
                                    "--work", work, "--srv-ns", srv, "--client", args.client, "--runs", str(args.runs),
                                    "--out", os.path.abspath(args.out), "--flows", str(args.flows),
                                    "--burst", str(args.burst), "--burst-at", str(args.burst_at),
                                    "--duration", str(args.duration)]
                                   + [x for s in args.server for x in ("--server", s)])
        stack.callback(stand.reap, measure, 15.0)
        limit = len(servers) * args.runs * (stand.READY_TIMEOUT + args.duration + 30) + 60
        try:
            code = measure.wait(limit)
        except subprocess.TimeoutExpired:
            print(f"the measurement did not finish within {limit:.0f} s; stopping it", file=sys.stderr)
            code = 1
    return code


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origin", help="binary built from ./origin")
    ap.add_argument("--client", required=True, help="Xray binary used as the client")
    ap.add_argument("--server", action="append", required=True, metavar="NAME=PATH",
                    help="Xray binary used as the server; repeat for each build to compare")
    ap.add_argument("--h2flow", action="append", metavar="NAME=JSON",
                    help='"h2Flow" object of that server instead of {"enabled": true}')
    ap.add_argument("--client-h2flow", metavar="JSON",
                    help='"h2Flow" object of the client, for a client that has the governor; none by default')
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--flows", type=int, default=4, help="outside TCP downloads in the burst")
    ap.add_argument("--burst", type=float, default=20.0, help="seconds the outside flows run")
    ap.add_argument("--burst-at", type=float, default=10.0, help="seconds into the download the burst starts")
    ap.add_argument("--duration", type=float, default=45.0, help="seconds the download is read")
    ap.add_argument("--mbit", type=int, default=60, help="link rate")
    ap.add_argument("--rtt", type=int, default=144, help="round trip of the link, ms")
    ap.add_argument("--queue-bdp", type=float, default=5.0,
                    help="the link's queue in bandwidth-delay products; a busy provider's is deep")
    ap.add_argument("--server-cc", default="cubic", help="TCP congestion control of the server's namespace")
    ap.add_argument("--connections", type=int, default=3, help="xmux.maxConnections of the client")
    ap.add_argument("--out", default="burst.jsonl", help="one JSON line per run, appended")
    ap.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--work", help=argparse.SUPPRESS)
    ap.add_argument("--srv-ns", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.inside:
        sys.exit(inside(args))
    if not args.origin:
        ap.error("--origin is required")
    sys.exit(outer(args))


if __name__ == "__main__":
    main()

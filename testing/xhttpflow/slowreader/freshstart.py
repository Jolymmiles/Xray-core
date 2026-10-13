#!/usr/bin/env python3
"""How fast a fresh download starts on a connection that has carried something.

An Xray client and server stand on the link of stand.py, 100 Mbit/s and a
round trip of 50 ms unless given. Each run starts both, moves --before over
the tunnel (an upload, a download, or nothing), and then times a download of
--bytes several times: --starts of them, each after --idle seconds in which
nothing is sent. A connection idle that long restarts from its initial
congestion window, so what the download finds is what the kernel kept for
the connection: with CUBIC, the slow start threshold.

It needs what stand.py needs, and ss from iproute2:

  go build -o origin ./testing/xhttpflow/slowreader/origin
  sudo python3 testing/xhttpflow/slowreader/freshstart.py \\
      --origin ./origin --client /path/to/xray-client \\
      --server stock=/path/to/xray --h2flow 'stock={"enabled": false}' \\
      --server before=/path/to/xray-before --server after=/path/to/xray-after \\
      --before upload --runs 6

Every --server build runs --runs times, all runs shuffled together, and each
run gives --starts times. Only the first of them follows --before; the later
ones follow a timed download on the same connection, so the table gives the
two apart: median, least and most, and how many took longer than --slow
seconds. --server-cc sets the server's
congestion control as in stand.py. HyStart is the host's, not a namespace's
(/sys/module/tcp_cubic/parameters/hystart), so the stand leaves it alone; to
measure without it, set it by hand on a host that runs nothing else and put
it back.

--client-h2flow '{"enabled": true}' turns the governor on in the client as
well, which needs a client built with it.

With --connections 1 every download uses the connection that carried
--before; with the 3 of stand.py a download lands on any of three, and only
some of them carried it.

After --before each run also reads, with ss, the slow start threshold and
the congestion window of the server's connections, in packets; a connection
that has not left slow start has no threshold. After the idle time the kernel
cuts the window back towards the initial one and sets the threshold to the
larger of the old one and three quarters of the window it had: that is what
the next download slow-starts up to. A run whose ss fails is invalid.

A run is valid if the tunnel came up, --before was moved whole, the server's
TCP state could be read, and every timed download was read whole within its
deadline. What the two Xray processes of an invalid run wrote is printed.
Invalid runs are reported and left out, and a single one makes the stand
exit with status 1.
"""

import argparse
import contextlib
import json
import os
import random
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

import stand

BEFORE_BYTES = {"upload": 30_000_000, "download": 60_000_000, "nothing": 0}
MOVE_TIMEOUT = 60.0


def request(head, deadline, body=0, length=None, text=None):
    """Sends a request through the tunnel, with body bytes of zeros after
    its head, and returns the seconds from the first byte sent to the last
    byte of the response read. Raises OSError unless the response is a 200
    that is whole before the deadline, with a body of length bytes if length
    is given and equal to text if text is."""
    s = stand.socks(deadline)
    try:
        start = time.time()
        s.settimeout(stand.time_left(deadline))
        s.sendall(head)
        block = bytes(65536)
        while body > 0:
            s.settimeout(stand.time_left(deadline))
            s.sendall(block[:min(body, len(block))])
            body -= min(body, len(block))
        buf = b""
        while b"\r\n\r\n" not in buf:
            s.settimeout(stand.time_left(deadline))
            chunk = s.recv(65536)
            if not chunk:
                raise OSError("closed before the headers ended")
            buf += chunk
        head, _, got = buf.partition(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 200"):
            raise OSError(f"answered {head.splitlines()[0]!r}")
        declared = re.search(rb"(?i)\r\ncontent-length: *(\d+)", head)
        if not declared:
            raise OSError("no Content-Length")
        declared = int(declared.group(1))
        if length is not None and declared != length:
            raise OSError(f"a body of {declared} bytes, not the {length} asked for")
        left = declared - len(got)
        kept = got if text is not None else b""
        while left > 0:
            s.settimeout(stand.time_left(deadline))
            chunk = s.recv(min(left, 262144))
            if not chunk:
                raise OSError(f"closed with {left} bytes to come")
            left -= len(chunk)
            if text is not None:
                kept += chunk
        end = time.time()
        if end >= deadline:
            raise OSError("the last byte came after the deadline")
        if text is not None and kept != text:
            raise OSError(f"answered {kept[:40]!r}, not {text!r}")
        return end - start
    finally:
        s.close()


def fetch(size, deadline):
    """Downloads size bytes; a response of another length is no download."""
    return request(b"GET /down?bytes=%d HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n" % size,
                   deadline, length=size)


def send(size, deadline):
    """Uploads size bytes; the origin answers with the number it read."""
    return request(b"POST /up?rate=0 HTTP/1.1\r\nHost: target.test\r\nContent-Length: %d\r\n"
                   b"Connection: close\r\n\r\n" % size, deadline, body=size, text=b"%d" % size)


def tcp_state(srv_ns):
    """What the server's kernel holds for its connections: their slow start
    thresholds and their congestion windows, in packets. A connection that
    has not left slow start has no threshold. Raises OSError if ss fails or
    names no connection: that is no measurement, not "no threshold"."""
    try:
        ss = subprocess.run(["ip", "netns", "exec", srv_ns, "ss", "-tinH", "sport = :443"],
                            capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as e:
        raise OSError(f"ss did not finish: {e}") from e
    if ss.returncode:
        raise OSError(f"ss failed with status {ss.returncode}: {ss.stderr.strip()}")
    out = ss.stdout
    cwnd = sorted(int(x) for x in re.findall(r"(?<![a-z_])cwnd:(\d+)", out))
    if not cwnd:
        raise OSError("ss showed no connection of the server")
    return sorted(int(x) for x in re.findall(r"(?<![a-z_])ssthresh:(\d+)", out)), cwnd


def one_run(server_binary, args, name):
    with contextlib.ExitStack() as stack:
        server, client = stand.start_xray(stack, server_binary, args, name)
        ready_by = time.time() + stand.READY_TIMEOUT
        while stand.ping(2) is None:
            if time.time() > ready_by or server.poll() is not None or client.poll() is not None:
                return {"invalid": "the tunnel did not come up"}
            time.sleep(0.2)
        try:
            if args.before == "upload":
                send(BEFORE_BYTES["upload"], time.time() + MOVE_TIMEOUT)
            elif args.before == "download":
                fetch(BEFORE_BYTES["download"], time.time() + MOVE_TIMEOUT)
        except OSError as e:
            return {"invalid": f"the {args.before} before the starts failed: {e}"}
        try:
            ssthresh, cwnd = tcp_state(args.srv_ns)
        except OSError as e:
            return {"invalid": f"the server's TCP state could not be read: {e}"}
        starts = []
        for _ in range(args.starts):
            time.sleep(args.idle)
            try:
                starts.append(fetch(args.bytes, time.time() + MOVE_TIMEOUT))
            except OSError as e:
                return {"invalid": f"a timed download failed: {e}", "starts": starts}
        return {"starts": starts, "ssthresh": ssthresh, "cwnd": cwnd}


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
                # The work directory goes with the stand; what Xray wrote
                # before the failure is shown first.
                stand.show_xray_logs(args.work)
                raise
            out.write(json.dumps({"server": name, "before": args.before, **r}) + "\n")
            out.flush()
            if "invalid" in r:
                invalid[name] += 1
                print(f"[{i}/{len(jobs)}] {name}: INVALID, {r['invalid']}", flush=True)
                stand.show_xray_logs(args.work)
                continue
            results[name].append(r)
            print(f"[{i}/{len(jobs)}] {name}: " + " ".join(f"{s:.2f}" for s in r["starts"])
                  + f" s, ssthresh {r['ssthresh'] or 'none'}, cwnd {r['cwnd']}", flush=True)

    print("\n| | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))

    def first(rs):
        return [r["starts"][0] for r in rs]

    def later(rs):
        return [s for r in rs for s in r["starts"][1:]]

    def packets(rs, key):
        values = [x for r in rs for x in r[key]]
        return f"{min(values)}-{max(values)}" if values else "none"

    def times(starts):
        if not starts:
            return "-"
        return (f"{statistics.median(starts):.2f} ({min(starts):.2f}-{max(starts):.2f}) s, "
                f"{sum(s > args.slow for s in starts)} of {len(starts)} over {args.slow:g}")

    rows = [
        ("Valid runs", lambda n, rs: f"{len(rs)} of {len(rs) + invalid[n]}"),
        (f"First start, after {args.before}: median (least-most)", lambda n, rs: times(first(rs))),
        ("Later starts, after a timed download", lambda n, rs: times(later(rs))),
        ("Server ssthresh before the starts, packets", lambda n, rs: packets(rs, "ssthresh")),
        ("Server cwnd before the starts, packets", lambda n, rs: packets(rs, "cwnd")),
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
    srv, cli = f"xfresh-{os.getpid()}-srv", f"xfresh-{os.getpid()}-cli"
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    code = None
    with contextlib.ExitStack() as stack:
        work = tempfile.mkdtemp(prefix="freshstart-")
        stack.callback(shutil.rmtree, work, ignore_errors=True)
        origin_log = stack.enter_context(open(f"{work}/origin.log", "w+b"))

        def show_origin_log(exc_type, exc, tb):
            if code != 0 or exc_type is not None:
                stand.show_log("origin", origin_log)

        stack.push(show_origin_log)
        stand.setup_network(stack, srv, cli, args.mbit, args.rtt, 0, args.server_cc)
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
                                    "--out", os.path.abspath(args.out), "--before", args.before,
                                    "--starts", str(args.starts), "--idle", str(args.idle), "--bytes", str(args.bytes),
                                    "--slow", str(args.slow)]
                                   + [x for s in args.server for x in ("--server", s)])
        stack.callback(stand.reap, measure, 15.0)
        per_run = stand.READY_TIMEOUT + 2 + MOVE_TIMEOUT + args.starts * (args.idle + MOVE_TIMEOUT) + 30
        limit = len(servers) * args.runs * per_run + 60
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
    ap.add_argument("--runs", type=int, default=6)
    ap.add_argument("--before", choices=tuple(BEFORE_BYTES), default="upload",
                    help="what the connection carries before the timed downloads")
    ap.add_argument("--starts", type=int, default=4, help="timed downloads in a run")
    ap.add_argument("--idle", type=float, default=3.0, help="seconds without traffic before each timed download")
    ap.add_argument("--bytes", type=int, default=3_000_000, help="size of a timed download")
    ap.add_argument("--slow", type=float, default=0.7, help="a start over this many seconds is counted")
    ap.add_argument("--mbit", type=int, default=stand.MBIT, help="link rate")
    ap.add_argument("--rtt", type=int, default=stand.RTT_MS, help="round trip of the link, ms")
    ap.add_argument("--server-cc", default="cubic", help="TCP congestion control of the server's namespace")
    ap.add_argument("--connections", type=int, default=3, help="xmux.maxConnections of the client")
    ap.add_argument("--out", default="freshstart.jsonl", help="one JSON line per run, appended")
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

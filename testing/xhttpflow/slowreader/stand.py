#!/usr/bin/env python3
"""Slow-reader stand for the XHTTP HTTP/2 flow governor.

Twenty uploads run through an Xray client and server into an origin that reads
100 KB/s from each, while a small request is sent every 0.3 s on the same
connections. The stand reports how long those requests take and how much
memory the server holds, for each server build given.

It needs root on Linux (network namespaces, netem), python3, iproute2, and:

  go build -o origin ./testing/xhttpflow/slowreader/origin
  sudo python3 testing/xhttpflow/slowreader/stand.py \\
      --origin ./origin --client /path/to/xray-client \\
      --server before=/path/to/xray-before --server after=/path/to/xray-after \\
      --runs 36

Every --server build runs --runs times, all runs shuffled together. The server
has the governor on ("h2Flow": {"enabled": true}); the client is whatever
--client is, with its own defaults. REALITY keys are made on the spot with
"<first server> x25519" and live in a temporary directory.

The stand creates two network namespaces and a veth pair with names of its
own (xslow-<pid>-...), refuses to start if they exist, and removes them, the
temporary directory and every process it started when it ends, however it
ends short of SIGKILL; a namespace it cannot remove makes it fail with the
error. It touches nothing else on the host. The measurement gets RUN_LIMIT
(98 s) per run, where a run normally takes its 12 s of load and a few seconds
around them; one still going past that is stuck, and the stand stops it,
tears down and exits with status 1. Origin's stderr is kept in the temporary
directory and printed when the stand fails.

A run is valid only if every upload was still sending at the deadline and the
server's memory could be read. A small request that fails or does not finish
within 10 s counts as a 10 s sample, so a stall can only make a run worse.
Invalid runs are reported and left out of the table, and a single one makes
the stand exit with status 1: the table and the JSON lines still come out,
but the comparison is incomplete.
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

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SOCKS = ("127.0.0.1", 21080)
TARGET, TARGET_PORT = b"target.test", 18000
XMUX = {"maxConnections": 3, "maxConcurrency": 0, "cMaxReuseTimes": 0,
        "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000", "hKeepAlivePeriod": 16}
MBIT, RTT_MS = 100, 50
UPLOADS, UPLOAD_RATE, DURATION, PING_EVERY = 20, 100_000, 12, 0.3
PING_TIMEOUT, READY_TIMEOUT = 10.0, 20.0
# What one run's own waits allow at most: readiness and its last ping, the
# workload and the uploads' join, both watchers' joins; and half a minute for
# starting and stopping Xray. The parent gives the measurement this per run.
RUN_LIMIT = (READY_TIMEOUT + 2) + (DURATION + PING_TIMEOUT) + 2 * (PING_TIMEOUT + 2) + 30


def sh(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def reap(proc, grace=0.0):
    """Stop a child and wait for it: SIGTERM first if it gets grace seconds
    to clean up after itself, then SIGKILL."""
    if proc.poll() is None and grace:
        proc.terminate()
        try:
            proc.wait(grace)
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def remove_namespace(ns):
    """Kills whatever still runs in a namespace of this run and deletes it;
    that removes the veth end inside it, and its peer. If either step fails
    it raises, after trying both: the ExitStack still runs the rest of the
    teardown, and the stand ends with the error instead of a success."""
    errors = []
    listed = subprocess.run(["ip", "netns", "pids", ns], capture_output=True, text=True)
    if listed.returncode:
        errors.append(f"ip netns pids: {listed.stderr.strip()}")
    for pid in listed.stdout.split():
        with contextlib.suppress(ProcessLookupError, ValueError):
            os.kill(int(pid), signal.SIGKILL)
    deleted = subprocess.run(["ip", "netns", "del", ns], capture_output=True, text=True)
    if deleted.returncode:
        errors.append(f"ip netns del: {deleted.stderr.strip()}")
    if errors:
        raise RuntimeError(f"network namespace {ns} may be left behind: " + "; ".join(errors))


def setup_network(stack, srv, cli):
    """Two namespaces of this run joined by a veth pair, shaped in both."""
    existing = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True).stdout.split()
    for ns in (srv, cli):
        if ns in existing:
            sys.exit(f"network namespace {ns} already exists; not touching it")
    for ns in (srv, cli):
        sh(f"ip netns add {ns}")
        stack.callback(remove_namespace, ns)
    pid = os.getpid()
    vsrv, vcli = f"xs{pid}s", f"xs{pid}c"
    sh(f"ip link add {vsrv} netns {srv} type veth peer name {vcli} netns {cli}")
    sh(f"ip -n {srv} addr add 10.9.0.1/24 dev {vsrv}")
    sh(f"ip -n {cli} addr add 10.9.0.2/24 dev {vcli}")
    # netem drops what exceeds its queue, so the queue holds twice the
    # bandwidth-delay product: the windows, not the queue, limit the flows.
    limit = max(1000, int(MBIT * 1e6 / 8 * RTT_MS / 1000 / 1500 * 2))
    for ns, dev in ((srv, vsrv), (cli, vcli)):
        sh(f"ip -n {ns} link set lo up")
        sh(f"ip -n {ns} link set {dev} up")
        sh(f'ip netns exec {ns} sysctl -qw net.ipv4.tcp_rmem="4096 131072 33554432" '
           f'net.ipv4.tcp_wmem="4096 16384 33554432"')
        sh(f"ip netns exec {ns} tc qdisc replace dev {dev} root netem delay {RTT_MS / 2:g}ms rate {MBIT}mbit limit {limit}")
    subprocess.run(["ip", "netns", "exec", srv, "sysctl", "-qw", "net.ipv4.tcp_congestion_control=cubic"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def reality_keys(xray):
    out = subprocess.run([xray, "x25519"], check=True, capture_output=True, text=True).stdout
    values = [line.split(":", 1)[1].strip() for line in out.splitlines() if ":" in line]
    if len(values) < 2:
        sys.exit(f"cannot read REALITY keys from '{xray} x25519'")
    return values[0], values[1]


def server_config(private_key):
    return {"log": {"loglevel": "error"}, "dns": {"hosts": {"target.test": "127.0.0.1"}},
            "inbounds": [{"listen": "10.9.0.1", "port": 443, "protocol": "vless",
                          "settings": {"clients": [{"id": UUID, "email": "u@x"}], "decryption": "none"},
                          "streamSettings": {"network": "xhttp", "security": "reality",
                                             "xhttpSettings": {"extra": {"xmux": XMUX, "h2Flow": {"enabled": True}}},
                                             "realitySettings": {"target": "127.0.0.1:8444", "shortIds": ["ab12"],
                                                                 "privateKey": private_key,
                                                                 "serverNames": ["www.example.com"]}}}],
            "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP",
                                                               "finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}}]}


def client_config(public_key):
    return {"log": {"loglevel": "error"},
            "inbounds": [{"listen": SOCKS[0], "port": SOCKS[1], "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "10.9.0.1", "port": 443,
                                                                         "users": [{"id": UUID, "encryption": "none"}]}]},
                           "streamSettings": {"network": "xhttp", "security": "reality",
                                              "realitySettings": {"serverName": "www.example.com", "fingerprint": "chrome",
                                                                  "publicKey": public_key, "shortId": "ab12"},
                                              "xhttpSettings": {"extra": {"xmux": XMUX}}}}]}


def outer(args):
    """Sets the stand up, runs the measurement inside the client namespace, tears everything down."""
    if os.geteuid() != 0:
        sys.exit("needs root: it creates network namespaces")
    servers = dict(s.split("=", 1) for s in args.server)
    srv, cli = f"xslow-{os.getpid()}-srv", f"xslow-{os.getpid()}-cli"
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    code = None
    with contextlib.ExitStack() as stack:
        work = tempfile.mkdtemp(prefix="slowreader-")
        stack.callback(shutil.rmtree, work, ignore_errors=True)
        # Origin logs its own errors. Unless the stand succeeds, including its
        # teardown, they are shown after the rest is torn down and before the
        # directory goes.
        origin_log = stack.enter_context(open(f"{work}/origin.log", "w+b"))

        def show_origin_log(exc_type, exc, tb):
            if code != 0 or exc_type is not None:
                show_log("origin", origin_log)

        stack.push(show_origin_log)
        setup_network(stack, srv, cli)
        private_key, public_key = reality_keys(next(iter(servers.values())))
        with open(f"{work}/server.json", "w") as f:
            json.dump(server_config(private_key), f)
        with open(f"{work}/client.json", "w") as f:
            json.dump(client_config(public_key), f)
        origin = subprocess.Popen(["ip", "netns", "exec", srv, args.origin],
                                  stdout=subprocess.DEVNULL, stderr=origin_log)
        stack.callback(reap, origin)
        inside = subprocess.Popen(["ip", "netns", "exec", cli, sys.executable, os.path.abspath(__file__), "--inside",
                                   "--work", work, "--srv-ns", srv, "--client", args.client, "--runs", str(args.runs),
                                   "--out", os.path.abspath(args.out)] + [x for s in args.server for x in ("--server", s)])
        stack.callback(reap, inside, 15.0)  # it stops and reaps its own Xray processes
        # Past this the child is stuck, not slow; leaving here tears it down.
        limit = len(servers) * args.runs * RUN_LIMIT + 60
        try:
            code = inside.wait(limit)
        except subprocess.TimeoutExpired:
            print(f"the measurement did not finish within {limit:.0f} s; stopping it", file=sys.stderr)
            code = 1
    return code


def show_log(name, f):
    """Prints what a child wrote to f, if anything."""
    f.seek(0)
    text = f.read().decode(errors="replace").rstrip()
    if text:
        print(f"{name} stderr:\n{text}", file=sys.stderr)


def time_left(deadline):
    """Seconds until deadline, for the next socket operation; socket.timeout
    once it has passed, so no operation starts late."""
    left = deadline - time.time()
    if left <= 0:
        raise socket.timeout("deadline passed")
    return left


def socks(deadline):
    """A TCP connection to the origin through the client's SOCKS5 inbound."""
    s = socket.create_connection(SOCKS, timeout=time_left(deadline))
    try:
        s.settimeout(time_left(deadline))
        s.sendall(b"\x05\x01\x00")
        if recv_exact(s, 2, deadline) != b"\x05\x00":
            raise OSError("socks: method refused")
        s.settimeout(time_left(deadline))
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(TARGET)]) + TARGET + TARGET_PORT.to_bytes(2, "big"))
        reply = recv_exact(s, 10, deadline)
        if reply[:2] != b"\x05\x00":
            raise OSError(f"socks: connect failed with code {reply[1]}")
        return s
    except BaseException:
        s.close()
        raise


def recv_exact(s, n, deadline):
    buf = b""
    while len(buf) < n:
        s.settimeout(time_left(deadline))
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("closed early")
        buf += chunk
    return buf


def ping(timeout=PING_TIMEOUT):
    """Milliseconds for one small request through the tunnel, or None if it
    failed or did not finish within timeout: session, GET /ping, 200, "pong".
    One deadline covers the whole request: every send and receive gets only
    the time left, and an answer complete after it is a failure too."""
    start = time.time()
    deadline = start + timeout
    try:
        s = socks(deadline)
        try:
            s.settimeout(time_left(deadline))
            s.sendall(b"GET /ping HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n")
            # The answer is the status line, headers and the four bytes of
            # "pong". The tunnel passes the origin's close on only after a
            # while, so the time is taken when the body is in, not at EOF.
            want = b"\r\n\r\npong"
            buf = b""
            while want not in buf and len(buf) < 4096:
                s.settimeout(time_left(deadline))
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        end = time.time()
        head, _, body = buf.partition(b"\r\n\r\n")
        if end >= deadline or not head.startswith(b"HTTP/1.1 200") or body != b"pong":
            return None
        return (end - start) * 1000
    except OSError:
        return None


def upload(deadline, result):
    """Sends until deadline. result gets the bytes sent and how it ended."""
    sent = 0
    try:
        s = socks(time.time() + PING_TIMEOUT)
    except OSError as e:
        result.update(sent=0, end=f"no session: {e}")
        return
    try:
        s.settimeout(time_left(deadline))
        s.sendall(b"POST /up?rate=%d HTTP/1.1\r\nHost: target.test\r\nContent-Length: 500000000\r\n"
                  b"Connection: close\r\n\r\n" % UPLOAD_RATE)
        block = os.urandom(32768)
        while time.time() < deadline:
            # A send may wait for seconds while the origin drains; only the
            # deadline ends it.
            s.settimeout(max(0.05, deadline - time.time()))
            try:
                s.sendall(block)
            except socket.timeout:
                break
            sent += len(block)
        result.update(sent=sent, end="deadline")
    except OSError as e:
        result.update(sent=sent, end=f"error: {e}")
    finally:
        s.close()


def rss_bytes(pid):
    with open(f"/proc/{pid}/statm") as f:
        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


def percentile(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(p * len(values)))]


def one_run(server_binary, args):
    """One run. Returns its numbers, with "invalid" set to the reason if it must not count."""
    with contextlib.ExitStack() as stack:
        server = subprocess.Popen(["ip", "netns", "exec", args.srv_ns, server_binary, "run", "-c", f"{args.work}/server.json"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(reap, server)  # "ip netns exec" execs Xray in place, so this is Xray
        client = subprocess.Popen([args.client, "run", "-c", f"{args.work}/client.json"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(reap, client)

        ready_by = time.time() + READY_TIMEOUT
        while ping(2) is None:
            if time.time() > ready_by or server.poll() is not None or client.poll() is not None:
                return {"invalid": "the tunnel did not come up"}
            time.sleep(0.2)

        stop = threading.Event()
        latencies, failures, rss, rss_errors = [], [0], [], [0]

        def prober():
            while not stop.is_set():
                ms = ping()
                if ms is None:
                    failures[0] += 1
                    ms = PING_TIMEOUT * 1000
                latencies.append(ms)
                stop.wait(PING_EVERY)

        def sampler():
            while not stop.is_set():
                try:
                    rss.append(rss_bytes(server.pid))
                except (OSError, ValueError, IndexError):
                    rss_errors[0] += 1
                stop.wait(0.25)

        watchers = [threading.Thread(target=f, daemon=True) for f in (prober, sampler)]
        for t in watchers:
            t.start()
        deadline = time.time() + DURATION
        outcomes = [{} for _ in range(UPLOADS)]
        uploads = [threading.Thread(target=upload, args=(deadline, o), daemon=True) for o in outcomes]
        for t in uploads:
            t.start()
        for t in uploads:
            t.join(max(0, deadline + PING_TIMEOUT - time.time()))
        stop.set()
        for t in watchers:
            t.join(PING_TIMEOUT + 2)

        run = {"p50": percentile(latencies, 0.5) if latencies else None,
               "p95": percentile(latencies, 0.95) if latencies else None,
               "pings": len(latencies), "pings_failed": failures[0],
               "rss_mb": max(rss) / 2**20 if rss else None,
               "upload_mb": sum(o.get("sent", 0) for o in outcomes) / 1e6}
        bad = [o.get("end", "still running") for o in outcomes if o.get("end") != "deadline" or not o.get("sent")]
        if any(t.is_alive() for t in uploads + watchers):
            run["invalid"] = "a driver did not finish"
        elif bad:
            run["invalid"] = f"{len(bad)} of {UPLOADS} uploads stopped early or sent nothing ({bad[0]})"
        elif not latencies:
            run["invalid"] = "no request was sent"
        elif not rss or rss_errors[0]:
            run["invalid"] = "the server's memory could not be read"
        elif server.poll() is not None or client.poll() is not None:
            run["invalid"] = "Xray exited during the run"
        return run


def inside(args):
    """The measurement itself; runs in the client namespace."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    servers = dict(s.split("=", 1) for s in args.server)
    results = {name: [] for name in servers}
    invalid = {name: 0 for name in servers}
    jobs = [name for name in servers for _ in range(args.runs)]
    random.shuffle(jobs)
    with open(args.out, "a") as out:
        for i, name in enumerate(jobs, 1):
            r = one_run(servers[name], args)
            out.write(json.dumps({"server": name, **r}) + "\n")
            out.flush()
            if "invalid" in r:
                invalid[name] += 1
                print(f"[{i}/{len(jobs)}] {name}: INVALID, {r['invalid']}", flush=True)
                continue
            results[name].append(r)
            print(f"[{i}/{len(jobs)}] {name}: ping p50 {r['p50']:.0f} ms, p95 {r['p95']:.0f} ms, "
                  f"{r['pings_failed']} of {r['pings']} failed, server peak RSS {r['rss_mb']:.1f} MB", flush=True)

    print("\n| | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))
    rows = [
        ("Valid runs", lambda n, rs: f"{len(rs)} of {len(rs) + invalid[n]}"),
        ("Requests failed or over 10 s", lambda n, rs: f"{sum(r['pings_failed'] for r in rs)} of {sum(r['pings'] for r in rs)}"),
        ("Runs with ping p95 above 2 s", lambda n, rs: str(sum(r["p95"] > 2000 for r in rs))),
        ("Worst ping p95", lambda n, rs: f"{max(r['p95'] for r in rs) / 1000:.2f} s"),
        ("Median ping p50 / p95", lambda n, rs: f"{statistics.median(r['p50'] for r in rs):.0f} / "
                                                 f"{statistics.median(r['p95'] for r in rs):.0f} ms"),
        ("Median server peak RSS", lambda n, rs: f"{statistics.median(r['rss_mb'] for r in rs):.1f} MB"),
    ]
    for label, f in rows:
        print(f"| {label} | " + " | ".join(f(n, rs) if rs else "-" for n, rs in results.items()) + " |")
    # A run left out of the table could be the one that shows the stall, so
    # a single invalid run makes the whole comparison fail.
    failed = sum(invalid.values())
    if failed:
        print(f"\n{failed} of {len(jobs)} runs were invalid: the comparison is incomplete", file=sys.stderr)
    return 1 if failed or not all(results.values()) else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origin", help="binary built from ./origin")
    ap.add_argument("--client", required=True, help="Xray binary used as the client")
    ap.add_argument("--server", action="append", required=True, metavar="NAME=PATH",
                    help="Xray binary used as the server; repeat for each build to compare")
    ap.add_argument("--runs", type=int, default=36)
    ap.add_argument("--out", default="slowreader.jsonl", help="one JSON line per run, appended")
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

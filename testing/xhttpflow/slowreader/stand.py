#!/usr/bin/env python3
"""Slow-reader stand for the XHTTP HTTP/2 flow governor.

Twenty uploads run through an Xray client and server into an origin that reads
100 KB/s from each, while a small request is sent every 0.3 s on the same
connections. The stand reports how long those requests take and how much
memory the server holds, for each server build given.

It needs root on Linux (network namespaces, netem), Python 3.12 or newer,
iproute2, and:

  go build -o origin ./testing/xhttpflow/slowreader/origin
  sudo python3 testing/xhttpflow/slowreader/stand.py \\
      --origin ./origin --client /path/to/xray-client \\
      --server before=/path/to/xray-before --server after=/path/to/xray-after \\
      --runs 36

Every --server build runs --runs times, all runs shuffled together. The server
has the governor on ("h2Flow": {"enabled": true}); the client is whatever
--client is, with its own defaults. REALITY keys are made on the spot with
"<first server> x25519", so nothing secret is stored here.
"""
import argparse
import json
import os
import random
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


def sh(cmd, check=True):
    subprocess.run(cmd, shell=True, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_network():
    """Two namespaces joined by a veth pair; the link is shaped in both."""
    for ns in ("srv", "cli"):
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip netns add {ns}")
    sh("ip link add vsrv type veth peer name vcli")
    sh("ip link set vsrv netns srv")
    sh("ip link set vcli netns cli")
    sh("ip -n srv addr add 10.9.0.1/24 dev vsrv")
    sh("ip -n cli addr add 10.9.0.2/24 dev vcli")
    for ns, dev in (("srv", "vsrv"), ("cli", "vcli")):
        sh(f"ip -n {ns} link set lo up")
        sh(f"ip -n {ns} link set {dev} up")
        sh(f'ip netns exec {ns} sysctl -qw net.ipv4.tcp_rmem="4096 131072 33554432" '
           f'net.ipv4.tcp_wmem="4096 16384 33554432"')
    sh("ip netns exec srv sysctl -qw net.ipv4.tcp_congestion_control=cubic", check=False)
    # netem drops what exceeds its queue, so the queue holds twice the
    # bandwidth-delay product: the windows, not the queue, limit the flows.
    limit = max(1000, int(MBIT * 1e6 / 8 * RTT_MS / 1000 / 1500 * 2))
    for ns, dev in (("srv", "vsrv"), ("cli", "vcli")):
        sh(f"ip netns exec {ns} tc qdisc replace dev {dev} root netem delay {RTT_MS / 2:g}ms rate {MBIT}mbit limit {limit}")


def reality_keys(xray):
    out = subprocess.run([xray, "x25519"], check=True, capture_output=True, text=True).stdout
    values = [line.split(":", 1)[1].strip() for line in out.splitlines() if ":" in line]
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


def socks(timeout=30):
    """A TCP connection to the origin through the client's SOCKS5 inbound."""
    s = socket.create_connection(SOCKS, timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(TARGET)]) + TARGET + TARGET_PORT.to_bytes(2, "big"))
    reply = b""
    while len(reply) < 10:
        chunk = s.recv(10 - len(reply))
        if not chunk:
            raise OSError("socks closed")
        reply += chunk
    return s


def ping(timeout=10):
    """Milliseconds from opening a session to the origin's answer, or None."""
    start = time.time()
    try:
        s = socks(timeout)
        s.sendall(b"GET /ping HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise OSError("closed before headers")
            buf += chunk
        s.close()
        return (time.time() - start) * 1000
    except OSError:
        return None


def upload(deadline):
    s = socks()
    s.sendall(b"POST /up?rate=%d HTTP/1.1\r\nHost: target.test\r\nContent-Length: 500000000\r\n"
              b"Connection: close\r\n\r\n" % UPLOAD_RATE)
    block = os.urandom(32768)
    try:
        while time.time() < deadline:
            s.settimeout(max(0.5, deadline - time.time()))
            s.sendall(block)
    except OSError:
        pass
    s.close()


def rss_bytes(pid):
    with open(f"/proc/{pid}/statm") as f:
        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


def percentile(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(p * len(values)))] if values else None


def one_run(server_binary, client_binary, work):
    server = subprocess.Popen(["ip", "netns", "exec", "srv", server_binary, "run", "-c", f"{work}/server.json"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client = subprocess.Popen([client_binary, "run", "-c", f"{work}/client.json"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        for _ in range(10):
            if ping(5) is not None:
                break
            time.sleep(0.5)
        else:
            return None
        server_pid = server.pid  # "ip netns exec" execs Xray in place
        stop = threading.Event()
        latencies, failures, rss = [], [0], []

        def prober():
            while not stop.is_set():
                ms = ping()
                if ms is None:
                    failures[0] += 1
                else:
                    latencies.append(ms)
                time.sleep(PING_EVERY)

        def sampler():
            while not stop.is_set():
                try:
                    rss.append(rss_bytes(server_pid))
                except OSError:
                    pass
                time.sleep(0.25)

        watchers = [threading.Thread(target=f, daemon=True) for f in (prober, sampler)]
        for t in watchers:
            t.start()
        deadline = time.time() + DURATION
        uploads = [threading.Thread(target=upload, args=(deadline,), daemon=True) for _ in range(UPLOADS)]
        for t in uploads:
            t.start()
        for t in uploads:
            t.join(DURATION + 30)
        stop.set()
        return {"p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95),
                "failed": failures[0], "rss_mb": max(rss or [0]) / 2**20}
    finally:
        for p in (client, server):
            p.kill()
        for p in (client, server):
            p.wait()
        time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origin", required=True, help="binary built from ./origin")
    ap.add_argument("--client", required=True, help="Xray binary used as the client")
    ap.add_argument("--server", action="append", required=True, metavar="NAME=PATH",
                    help="Xray binary used as the server; repeat for each build to compare")
    ap.add_argument("--runs", type=int, default=36)
    ap.add_argument("--out", default="slowreader.jsonl", help="one JSON line per run")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("needs root: it creates network namespaces")
    servers = dict(s.split("=", 1) for s in args.server)

    setup_network()
    work = tempfile.mkdtemp(prefix="slowreader-")
    private_key, public_key = reality_keys(next(iter(servers.values())))
    json.dump(server_config(private_key), open(f"{work}/server.json", "w"))
    json.dump(client_config(public_key), open(f"{work}/client.json", "w"))
    origin = subprocess.Popen(["ip", "netns", "exec", "srv", args.origin],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    os.setns(os.open("/var/run/netns/cli", os.O_RDONLY), os.CLONE_NEWNET)  # the client and the drivers live in "cli"

    results = {name: [] for name in servers}
    jobs = [name for name in servers for _ in range(args.runs)]
    random.shuffle(jobs)
    try:
        with open(args.out, "a") as out:
            for i, name in enumerate(jobs, 1):
                r = one_run(servers[name], args.client, work)
                if r is None:
                    print(f"[{i}/{len(jobs)}] {name}: no connectivity", flush=True)
                    continue
                results[name].append(r)
                out.write(json.dumps({"server": name, **r}) + "\n")
                out.flush()
                print(f"[{i}/{len(jobs)}] {name}: ping p50 {r['p50']:.0f} ms, p95 {r['p95']:.0f} ms, "
                      f"server peak RSS {r['rss_mb']:.1f} MB", flush=True)
    finally:
        origin.kill()

    print("\n| | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))
    rows = [
        ("Runs", lambda rs: str(len(rs))),
        ("Runs with ping p95 above 2 s", lambda rs: str(sum(r["p95"] > 2000 for r in rs))),
        ("Worst ping p95", lambda rs: f"{max(r['p95'] for r in rs) / 1000:.2f} s"),
        ("Median ping p50 / p95", lambda rs: f"{statistics.median(r['p50'] for r in rs):.0f} / "
                                              f"{statistics.median(r['p95'] for r in rs):.0f} ms"),
        ("Median server peak RSS", lambda rs: f"{statistics.median(r['rss_mb'] for r in rs):.1f} MB"),
    ]
    for label, f in rows:
        print(f"| {label} | " + " | ".join(f(rs) if rs else "-" for rs in results.values()) + " |")


if __name__ == "__main__":
    main()

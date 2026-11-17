#!/usr/bin/env python3
"""REALITY session resumption stand.

Run as `unshare -Urnm python3 stand.py <scenario>...` (root of a new user,
network and mount namespace, no real root needed). Two network namespaces:

  cli 10.9.0.1  --veth--  srv 10.9.0.2..
                                .11 nginx  .12 caddy  .13 haproxy      (targets)
                                .21-.23 REALITY, new build, target .11-.13
                                .31-.33 REALITY, old build, target .11-.13
                                .50 plain HTTP behind the proxies

Every scenario writes runs/<stamp>/<scenario>/: capture.pcap (taken on the
client's side of the veth: what a censor sees), keylog (TLS secrets of the
clients), meta.json, and logs. analyze.py reads them.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

S = os.environ.get("STAND_WORK") or os.path.expanduser("~/.cache/realitystand")
CODE = os.path.dirname(os.path.abspath(__file__))
R = S + "/root"
ENV = dict(os.environ)
ENV["PATH"] = f"{S}/bin:{R}/usr/sbin:{R}/usr/bin:{R}/sbin:" + ENV.get("PATH", "")
ENV["LD_LIBRARY_PATH"] = f"{R}/usr/lib/x86_64-linux-gnu:{R}/lib/x86_64-linux-gnu:{R}/usr/lib"

TARGETS = {"nginx": "10.9.0.11", "caddy": "10.9.0.12", "haproxy": "10.9.0.13"}
# targets only REALITY uses, not the browser references
EXTRA_TARGETS = {"nginxshort": "10.9.0.14"}  # tickets live 8 s
NEW_SERVER = {"nginx": "10.9.0.21", "caddy": "10.9.0.22", "haproxy": "10.9.0.23", "nginxshort": "10.9.0.24"}
XHTTP_SERVER = {"nginx": "10.9.0.25", "caddy": "10.9.0.26", "haproxy": "10.9.0.27", "stub": "10.9.0.62"}  # XHTTP, REALITY and VLESS encryption
ANGIE = shutil.which("angie", path=ENV["PATH"])
if ANGIE:
    TARGETS["angie"] = "10.9.0.15"
    NEW_SERVER["angie"] = "10.9.0.29"
    XHTTP_SERVER["angie"] = "10.9.0.28"
ENVOY = shutil.which("envoy", path=ENV["PATH"])
if ENVOY:
    TARGETS["envoy"] = "10.9.0.16"
    NEW_SERVER["envoy"] = "10.9.0.34"
    XHTTP_SERVER["envoy"] = "10.9.0.30"
VLESS_DECRYPTION = "mlkem768x25519plus.native.600s.4C-Jfmbk0JonPavemvoIorZ67XgTDcoQbNZ8QEDqhEI"
VLESS_ENCRYPTION = "mlkem768x25519plus.native.0rtt.IXfd7hgLhfrSnUecWr7SMtDrSBY6YHo-Gh107IJeHFE"
STUB = "10.9.0.60"  # REALITY in front of the operator's own site at 127.0.0.1:8443
LB = "10.9.0.40"  # HAProxy in TCP mode, round robin over the new and the old server for nginx
OLD_SERVER = {"nginx": "10.9.0.31", "caddy": "10.9.0.32", "haproxy": "10.9.0.33"}
HTTP = "10.9.0.50"
UUID = "4594f501-ab51-49d1-b3da-01435d922c4c"
PRIVATE_KEY = "4OhcQP9U1nW0dPjI2RNQSOADXBdW0LLuvgBrYrLFy0A"
PUBLIC_KEY = "Mb8smvtzEq99MlGhrlulWKEWaC2JgU_pRsyNsCQFEF8"
SHORT_ID = "0123456789abcdef"

procs = []  # (name, Popen), stopped by pid, never by name: pkill sees the host
captures = []  # tcpdump processes


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, shell=True, check=check, env=ENV, **kw)


def start(name, cmd, log):
    p = subprocess.Popen(cmd, shell=True, env=ENV, stdout=open(log, "wb"),
                         stderr=subprocess.STDOUT, start_new_session=True)
    procs.append((name, p))
    return p


def stop(p, sig=signal.SIGTERM, wait=5):
    if p.poll() is None:
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            return
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()


def stop_all():
    for _, p in reversed(procs):
        stop(p)
    procs.clear()
    for p in captures:
        p.kill()
        p.wait()
    captures.clear()


def wait_port(ns, ip, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(f"ip netns exec {ns} python3 -c \"import socket;socket.create_connection(('{ip}',{port}),1)\"",
                           shell=True, env=ENV, capture_output=True)
        if r.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError(f"{ip}:{port} did not come up")


def topology():
    sh("mount -t tmpfs none /run && mkdir -p /run/netns")
    hosts = f"{S}/runs/hosts"
    with open(hosts, "w") as f:
        f.write("127.0.0.1 localhost\n")
        for name, ip in {**TARGETS, **EXTRA_TARGETS}.items():
            f.write(f"{ip} {name}.example.test\n")
        f.write(f"{STUB} stub.example.test\n")
    sh(f"mount --bind {hosts} /etc/hosts")
    sh("ip netns add cli && ip netns add srv")
    sh("ip link add vc type veth peer name vs && ip link set vc netns cli && ip link set vs netns srv")
    sh("ip -n cli addr add 10.9.0.1/24 dev vc && ip -n cli link set vc up && ip -n cli link set lo up")
    sh("ip -n srv addr add 10.9.0.2/24 dev vs && ip -n srv link set vs up && ip -n srv link set lo up")
    for ip in list(TARGETS.values()) + list(EXTRA_TARGETS.values()) + list(NEW_SERVER.values()) + list(OLD_SERVER.values()) + [HTTP, LB, STUB] + list(XHTTP_SERVER.values()):
        sh(f"ip -n srv addr add {ip}/32 dev vs")
    sh("ip -n cli route add 10.9.0.0/24 dev vc 2>/dev/null || true")
    rtt = int(os.environ.get("RTT_MS", "60"))
    if rtt:
        # half the round trip each way, on both ends of the veth
        sh(f"ip netns exec cli /usr/sbin/tc qdisc add dev vc root netem delay {rtt // 2}ms")
        sh(f"ip netns exec srv /usr/sbin/tc qdisc add dev vs root netem delay {rtt // 2}ms")


def start_targets(run):
    os.makedirs(f"{S}/runs/nginx-tmp", exist_ok=True)
    start("nginx", f"ip netns exec srv nginx -c {S}/conf/nginx.conf -g 'daemon off;'", f"{run}/nginx.log")
    start("caddy", f"ip netns exec srv env HOME={S}/runs XDG_DATA_HOME={S}/runs/caddy caddy run --config {S}/conf/Caddyfile --adapter caddyfile", f"{run}/caddy.log")
    start("haproxy", f"ip netns exec srv haproxy -f {S}/conf/haproxy.cfg", f"{run}/haproxy.log")
    start("http", f"ip netns exec srv python3 -m http.server --bind {HTTP} 80 --directory {S}/www", f"{run}/http.log")
    if ANGIE:
        os.makedirs(f"{S}/runs/angie", exist_ok=True)
        start("angie", f"ip netns exec srv angie -p {S}/runs/angie -e stderr -c {S}/conf/angie.conf -g 'daemon off;'", f"{run}/angie.log")
    if ENVOY:
        start("envoy", f"ip netns exec srv envoy -c {S}/conf/envoy.yaml --concurrency 1",
              f"{run}/envoy.log")
    with open(f"{run}/upload_sink.py", "w") as f:
        f.write(UPLOAD_SINK)
    start("upload", f"ip netns exec srv python3 {run}/upload_sink.py {HTTP}", f"{run}/upload.log")
    for ip in TARGETS.values():
        wait_port("srv", ip, 443)
    wait_port("srv", HTTP, 80)


def server_config(binary_servers, browser=True):
    inbounds = []
    for name, ip in binary_servers.items():
        inbounds.append({
            "listen": ip, "port": 443, "protocol": "vless", "tag": f"in-{name}",
            "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": f"{ {**TARGETS, **EXTRA_TARGETS}[name]}:443", "serverNames": [f"{name}.example.test"],
                "privateKey": PRIVATE_KEY, "shortIds": [SHORT_ID]}},
        })
    if binary_servers is NEW_SERVER:
        for name, ip in XHTTP_SERVER.items():
            target = "127.0.0.1:8443" if name == "stub" else f"{TARGETS[name]}:443"
            inbounds.append({
                "listen": ip, "port": 443, "protocol": "vless", "tag": f"xhttp-{name}",
                "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": VLESS_DECRYPTION},
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/assets/v2", "mode": "auto"},
                                   "security": "reality", "realitySettings": {
                                       "target": target, "serverNames": [f"{name}.example.test"],
                                       "privateKey": PRIVATE_KEY, "shortIds": [SHORT_ID]}},
            })
        inbounds.append({
            "listen": STUB, "port": 443, "protocol": "vless", "tag": "in-stub",
            "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": "127.0.0.1:8443", "serverNames": ["stub.example.test"],
                "privateKey": PRIVATE_KEY, "shortIds": [SHORT_ID]}},
        })
        if browser:
            for inbound in inbounds:
                inbound["streamSettings"]["realitySettings"]["browser"] = "auto"
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}


def start_servers(run, old=True, *, browser=True, binary="xray-new"):
    with open(f"{run}/server-new.json", "w") as f:
        json.dump(server_config(NEW_SERVER, browser), f, indent=1)
    start("server-new", f"ip netns exec srv env SSL_CERT_FILE={S}/certs/real/root.pem {binary} run -c {run}/server-new.json", f"{run}/server-new.log")
    if old:
        with open(f"{run}/server-old.json", "w") as f:
            json.dump(server_config(OLD_SERVER), f, indent=1)
        start("server-old", f"ip netns exec srv env SSL_CERT_FILE={S}/certs/real/root.pem xray-old run -c {run}/server-old.json", f"{run}/server-old.log")
    for ip in NEW_SERVER.values():
        wait_port("srv", ip, 443)
    if old:
        for ip in OLD_SERVER.values():
            wait_port("srv", ip, 443)
    # REALITY probes the targets when it starts; let it finish.
    time.sleep(12)


def xhttp_client_config(server_ip, target, fingerprint, browser, keylog, port=1080):
    """XHTTP over REALITY with VLESS encryption and Vision."""
    cfg = client_config(server_ip, target, fingerprint, browser, keylog, port)
    out = cfg["outbounds"][0]
    out["settings"]["vnext"][0]["users"][0]["encryption"] = VLESS_ENCRYPTION
    out["streamSettings"]["network"] = "xhttp"
    out["streamSettings"]["xhttpSettings"] = {"path": "/assets/v2", "mode": "auto"}
    return cfg


def client_config(server_ip, target, fingerprint, browser, keylog, port=1080):
    # a real site's own name, else a stand target's
    server_name = target if "." in target else f"{target}.example.test"
    reality = {"fingerprint": fingerprint, "serverName": server_name,
               "password": PUBLIC_KEY, "shortId": SHORT_ID, "masterKeyLog": keylog}
    if browser:
        reality["browser"] = browser
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": server_ip, "port": 443,
                           "users": [{"id": UUID, "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
                           "streamSettings": {"network": "raw", "security": "reality", "realitySettings": reality}}]}


class Capture:
    """tcpdump on the client's side of the veth. Started without a shell and
    stopped by its own pid, so that it really stops."""

    def __init__(self, path):
        self.p = subprocess.Popen(["ip", "netns", "exec", "cli", "tcpdump", "-Z", "root", "-i", "vc", "-U",
                                   "-w", "-", "tcp port 443"], env=ENV, stdout=open(path, "wb"),
                                  stderr=subprocess.DEVNULL)
        captures.append(self.p)
        time.sleep(1)

    def close(self):
        time.sleep(1)
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        captures.remove(self.p)


def scenario_dir(run, name):
    d = f"{run}/{name}"
    os.makedirs(d, exist_ok=True)
    return d


UPLOAD_SINK = r"""
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        while n > 0:
            chunk = self.rfile.read(min(n, 65536))
            if not chunk:
                return
            n -= len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer((sys.argv[1], 81), H).serve_forever()
"""


def xray_traffic(run, name, server_ip, target, fingerprint, browser, config=None, *, binary="xray-new"):
    """Real traffic through a client: a 5 MB download, a 1 MB upload and a
    few small requests, as a user browsing would make."""
    d = scenario_dir(run, name)
    keylog = f"{d}/keylog"
    cfg = (config or client_config)(server_ip, target, fingerprint, browser, keylog)
    with open(f"{d}/client.json", "w") as f:
        json.dump(cfg, f, indent=1)
    cap = Capture(f"{d}/capture.pcap")
    client = start(f"client-{name}", f"ip netns exec cli {binary} run -c {d}/client.json", f"{d}/client.log")
    wait_port("cli", "127.0.0.1", 1080)
    curl = f"ip netns exec cli curl -sS -o /dev/null -w '%{{http_code}} %{{time_total}}' --max-time 60 --socks5-hostname 127.0.0.1:1080"
    results, failed = {}, []
    for label, cmd in (("download", f"{curl} http://{HTTP}/blob5m"),
                       ("upload", f"{curl} --data-binary @{S}/www/blob1m http://{HTTP}:81/upload"),
                       ("small1", f"{curl} http://{HTTP}/index.html"),
                       ("small2", f"{curl} http://{HTTP}/page.html"),
                       ("small3", f"{curl} http://{HTTP}/index.html?3")):
        response = subprocess.run(cmd, shell=True, env=ENV, capture_output=True, text=True)
        results[label] = response.stdout
        if response.returncode or not response.stdout.startswith("200 "):
            failed.append(f"{label} ({response.stdout.strip()} {response.stderr.strip()})")
        time.sleep(1)
    stop(client)
    procs.remove((f"client-{name}", client))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "xray-traffic", "server": server_ip, "target": target, "fingerprint": fingerprint,
                   "browser": browser, "http": results}, f, indent=1)
    if failed:
        raise RuntimeError(f"{name}: {', '.join(failed)}")


def xray_client(run, name, binary, server_ip, target, fingerprint, browser, dials, pause=1.0, pauses=None):
    """dials connections through an Xray client, each a new REALITY connection."""
    d = scenario_dir(run, name)
    keylog = f"{d}/keylog"
    with open(f"{d}/client.json", "w") as f:
        json.dump(client_config(server_ip, target, fingerprint, browser, keylog), f, indent=1)
    cap = Capture(f"{d}/capture.pcap")
    client = start(f"client-{name}", f"ip netns exec cli {binary} run -c {d}/client.json", f"{d}/client.log")
    wait_port("cli", "127.0.0.1", 1080)
    results = []
    for i in range(dials):
        r = subprocess.run(f"ip netns exec cli curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 "
                           f"--socks5-hostname 127.0.0.1:1080 http://{HTTP}/index.html?{i}",
                           shell=True, env=ENV, capture_output=True, text=True)
        results.append(r.stdout)
        time.sleep(pauses[i] if pauses else pause)
    stop(client)
    procs.remove((f"client-{name}", client))
    cap.close()
    meta = {"kind": "xray", "binary": binary, "server": server_ip, "target": target,
            "fingerprint": fingerprint, "browser": browser, "http": results}
    with open(f"{d}/meta.json", "w") as f:
        json.dump(meta, f, indent=1)
    return meta


PAGE_HOSTS = {name: f"{name}.example.test" for name in (*TARGETS, "stub")}
PAGE_PATH = {"stub": "/"}


def chrome(run, name, target, binary=None):
    d = scenario_dir(run, name)
    home = f"{d}/home"
    os.makedirs(f"{home}/.pki/nssdb", exist_ok=True)
    sh(f"certutil -d sql:{home}/.pki/nssdb -N --empty-password && "
       f"certutil -d sql:{home}/.pki/nssdb -A -t 'C,,' -n standca -i {S}/certs/real/root.pem")
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"chrome-{name}", f"ip netns exec cli env HOME={home} SSLKEYLOGFILE={d}/keylog "
              f"{binary or R + '/opt/google/chrome/chrome'} --headless=new --no-sandbox --disable-gpu --no-first-run "
              f"--disable-background-networking --disable-component-update --disable-sync "
              f"--remote-debugging-port=9222 --user-data-dir={home}/profile about:blank", f"{d}/chrome.log")
    wait_port("cli", "127.0.0.1", 9222, timeout=60)
    url = f"https://{PAGE_HOSTS[target]}{PAGE_PATH.get(target, '/page.html')}"
    subprocess.run(["ip", "netns", "exec", "cli", "curl", "-fsS", "-X", "PUT",
                    f"http://127.0.0.1:9222/json/new?{url}"], env=ENV, stdout=subprocess.DEVNULL, check=True)
    time.sleep(18)
    stop(p)
    procs.remove((f"chrome-{name}", p))
    cap.close()
    if os.path.getsize(f"{d}/capture.pcap") <= 24 or not os.path.getsize(f"{d}/keylog"):
        raise RuntimeError(f"{name} did not capture a browser TLS session")
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "chrome", "binary": binary, "target": target}, f, indent=1)


FIREFOXES = {"firefox": "firefox", "firefox156": f"{R}/opt/firefox-156.0.1/firefox",
             "firefox160": f"{R}/opt/firefox-160.0/firefox"}  # the system one is 153 ESR


def firefox(run, name, target, binary="firefox"):
    d = scenario_dir(run, name)
    profile = f"{d}/profile"
    os.makedirs(profile, exist_ok=True)
    sh(f"certutil -d sql:{profile} -N --empty-password && "
       f"certutil -d sql:{profile} -A -t 'C,,' -n standca -i {S}/certs/real/root.pem")
    with open(f"{profile}/user.js", "w") as f:
        for k, v in {"browser.shell.checkDefaultBrowser": False, "datareporting.policy.dataSubmissionEnabled": False,
                     "toolkit.telemetry.enabled": False, "app.update.enabled": False,
                     "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                     "browser.safebrowsing.malware.enabled": False, "browser.safebrowsing.phishing.enabled": False,
                     "extensions.update.enabled": False, "browser.startup.homepage_override.mstone": "ignore"}.items():
            f.write(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n")
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"firefox-{name}", f"ip netns exec cli env HOME={d} SSLKEYLOGFILE={d}/keylog MOZ_DISABLE_CONTENT_SANDBOX=1 "
              f"{binary} --headless --no-remote --profile {profile} https://{PAGE_HOSTS[target]}{PAGE_PATH.get(target, '/page.html')}",
              f"{d}/firefox.log")
    time.sleep(19)
    stop(p)
    procs.remove((f"firefox-{name}", p))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "firefox", "binary": binary, "target": target}, f, indent=1)


REPLAY = r"""
import socket, struct, sys, json
def records(addr, hello):
    s = socket.create_connection((addr, 443), 5)
    s.sendall(hello)
    s.settimeout(2)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except Exception:
        pass
    s.close()
    out = []
    while len(data) >= 5:
        n = 5 + struct.unpack(">H", data[3:5])[0]
        out.append([data[0], n])
        data = data[n:]
    return out
hello = open(sys.argv[1], "rb").read()
print(json.dumps({a: records(a, hello) for a in sys.argv[2:]}))
"""


def replay_probe(run, name, source):
    """A censor replays a client's ClientHello that offers a ticket, to the
    REALITY server and to the target, and compares the answers."""
    d = scenario_dir(run, name)
    if source is None:
        source = f"{run}/edge-replay-source"
        xray_client(run, "edge-replay-source", "xray-new", NEW_SERVER["nginx"], "nginx", "chrome", "auto", 2)
    out = subprocess.run(f"tshark -r {source}/capture.pcap -Y 'tls.handshake.extensions.psk.identities.length' "
                         f"-T fields -e tcp.stream", shell=True, env=ENV, capture_output=True, text=True).stdout.split()
    if not out:
        with open(f"{d}/meta.json", "w") as f:
            json.dump({"kind": "replay", "error": "no ClientHello with a ticket"}, f)
        return
    raw = subprocess.run(f"tshark -r {source}/capture.pcap -q -z follow,tcp,raw,{out[0]}", shell=True, env=ENV,
                         capture_output=True, text=True).stdout
    client = b"".join(bytes.fromhex(l.strip()) for l in raw.splitlines()
                      if l and not l.startswith(("	", "=", "Follow", "Filter", "Node")) and all(c in "0123456789abcdef" for c in l.strip()))
    n = 5 + int.from_bytes(client[3:5], "big")
    with open(f"{d}/hello.bin", "wb") as f:
        f.write(client[:n])
    with open(f"{d}/replay.py", "w") as f:
        f.write(REPLAY)
    cap = Capture(f"{d}/capture.pcap")
    r = subprocess.run(f"ip netns exec cli python3 {d}/replay.py {d}/hello.bin {NEW_SERVER['nginx']} {TARGETS['nginx']}",
                       shell=True, env=ENV, capture_output=True, text=True)
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "replay", "answers": json.loads(r.stdout or "{}"), "stderr": r.stderr[-500:]}, f, indent=1)


TICKET_PROBE = r"""
import json, socket, struct, sys

def records(addr, hello):
    s = socket.create_connection((addr, 443), 5)
    s.sendall(hello)
    s.settimeout(2)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except Exception:
        pass
    s.close()
    out = []
    while len(data) >= 5:
        n = 5 + struct.unpack(">H", data[3:5])[0]
        body = data[5:n]
        out.append([data[0], n] + (list(body[:2]) if data[0] == 21 else []))
        data = data[n:]
    return out

def psk(hello):
    # offset and length of the first PSK identity
    p = 5 + 4 + 2 + 32
    p += 1 + hello[p]
    p += 2 + struct.unpack(">H", hello[p:p+2])[0]
    p += 1 + hello[p]
    end = p + 2 + struct.unpack(">H", hello[p:p+2])[0]
    p += 2
    while p < end:
        t, l = struct.unpack(">HH", hello[p:p+4])
        if t == 41:
            q = p + 4 + 2
            return q + 2, struct.unpack(">H", hello[q:q+2])[0]
        p += 4 + l
    return None

def bad_binder(h):
    h = bytearray(h)
    h[-1] ^= 1
    return bytes(h)

addr = sys.argv[1]
browser = open(sys.argv[2], "rb").read()
ours = open(sys.argv[3], "rb").read()
result = {
    "browser ticket, bad binder": records(addr, bad_binder(browser)),
    "our ticket, bad binder, our ClientHello": records(addr, bad_binder(ours)),
}
bo, bn = psk(browser)
oo, on = psk(ours)
if bn == on:
    t = bytearray(browser)
    t[bo:bo+bn] = ours[oo:oo+on]
    result["our ticket, bad binder, browser ClientHello"] = records(addr, bytes(t))
else:
    result["our ticket, browser ClientHello"] = f"ticket lengths differ: {bn} {on}"
print(json.dumps(result))
"""


def resumed_hello(scenario):
    """The first ClientHello in a scenario's capture that offers a ticket."""
    out = subprocess.run(f"tshark -r {scenario}/capture.pcap -Y 'tls.handshake.extensions.psk.identities.length' "
                         f"-T fields -e tcp.stream", shell=True, env=ENV, capture_output=True, text=True).stdout.split()
    if not out:
        return None
    raw = subprocess.run(f"tshark -r {scenario}/capture.pcap -q -z follow,tcp,raw,{out[0]}", shell=True, env=ENV,
                         capture_output=True, text=True).stdout
    client = b"".join(bytes.fromhex(l.strip()) for l in raw.splitlines()
                      if l and not l.startswith(("\t", "=", "Follow", "Filter", "Node"))
                      and all(c in "0123456789abcdef" for c in l.strip()))
    return client[:5 + int.from_bytes(client[3:5], "big")]


def ticket_probe(run):
    """A censor takes tickets seen on the wire to the server with a binder
    it cannot compute. A server that issued the ticket refuses the binder
    (decrypt_error), whichever ClientHello carries it."""
    d = scenario_dir(run, "stub-ticket-probe")
    browser, ours = resumed_hello(f"{run}/chrome-stub"), resumed_hello(f"{run}/xray-chrome-stub")
    if browser is None or ours is None:
        with open(f"{d}/meta.json", "w") as f:
            json.dump({"kind": "probe", "error": "no resumed ClientHello"}, f)
        return
    for name, data in (("browser.bin", browser), ("ours.bin", ours), ("probe.py", TICKET_PROBE.encode())):
        with open(f"{d}/{name}", "wb") as f:
            f.write(data)
    cap = Capture(f"{d}/capture.pcap")
    r = subprocess.run(f"ip netns exec cli python3 {d}/probe.py {STUB} {d}/browser.bin {d}/ours.bin",
                       shell=True, env=ENV, capture_output=True, text=True)
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "probe", "answers": json.loads(r.stdout or "{}"), "stderr": r.stderr[-800:]}, f, indent=1)


# Real sites as targets: `pasta --config-net -- unshare -m python3 stand.py
# real [site...]`. pasta gives the outer namespace the Internet; REALITY runs
# there in front of each site, and the clients in "cli" behind the veth.
REAL_SITES = ["www.microsoft.com", "www.cloudflare.com", "ya.ru", "github.com", "www.lovelive-anime.jp"]


def topology_real(sites):
    """cli 10.9.0.1 --veth-- outer namespace 10.9.0.2 (Internet by pasta),
    REALITY for site i at 10.9.0.(70+i), plain HTTP at 10.9.0.50."""
    import socket
    real_ips = {site: socket.gethostbyname(site) for site in sites}  # before /etc/hosts points them here
    sh("mount -t tmpfs none /run && mkdir -p /run/netns")
    servers = {site: f"10.9.0.{70 + i}" for i, site in enumerate(sites)}
    hosts = f"{S}/runs/hosts-real"
    with open(hosts, "w") as f:
        f.write("127.0.0.1 localhost\n")
        for site, ip in servers.items():
            f.write(f"{ip} {site}\n")
    sh(f"mount --bind {hosts} /etc/hosts")
    sh("ip netns add cli")
    sh("ip link add vc type veth peer name vs && ip link set vc netns cli")
    sh("ip -n cli addr add 10.9.0.1/24 dev vc && ip -n cli link set vc up && ip -n cli link set lo up")
    sh("ip addr add 10.9.0.2/24 dev vs && ip link set vs up")
    for ip in list(servers.values()) + [HTTP]:
        sh(f"ip addr add {ip}/32 dev vs")
    return real_ips, servers


def chrome_revisits(run, name, site, server_ip, binary=None, visits=4, cache_bust=False):
    """Chrome visits a real site, then again over new connections: its
    sockets are killed in between and a new tab opened by DevTools."""
    d = scenario_dir(run, name)
    home = f"{d}/home"
    os.makedirs(f"{home}/.pki/nssdb", exist_ok=True)
    sh(f"certutil -d sql:{home}/.pki/nssdb -N --empty-password && "
       f"certutil -d sql:{home}/.pki/nssdb -A -t 'C,,' -n standroot -i {S}/certs/real/root.pem")
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"chrome-{name}", f"ip netns exec cli env HOME={home} SSLKEYLOGFILE={d}/keylog "
              f"{binary or R + '/opt/google/chrome/chrome'} --headless=new --no-sandbox --disable-gpu --no-first-run "
              f"--disable-background-networking --disable-component-update --disable-sync "
              f"--remote-debugging-port=9222 --user-data-dir={home}/profile https://{site}/", f"{d}/chrome.log")
    time.sleep(8)
    for visit in range(1, visits):
        sh(f"ip netns exec cli ss -K dst {server_ip} >/dev/null 2>&1", check=False)
        time.sleep(1)
        url = f"https://{site}/" + (f"?visit={visit}" if cache_bust else "")
        sh(f"ip netns exec cli curl -s -X PUT 'http://127.0.0.1:9222/json/new?{url}' >/dev/null", check=False)
        time.sleep(7)
    stop(p)
    procs.remove((f"chrome-{name}", p))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "chrome", "binary": binary, "target": site}, f, indent=1)


MARIONETTE = r"""
import json, socket, subprocess, sys, time
def recv(f):
    n = b""
    while not n.endswith(b":"):
        part = f.read(1)
        if not part:
            raise EOFError("Firefox closed the Marionette connection")
        n += part
    return json.loads(f.read(int(n[:-1])))
def send(s, f, i, name, params):
    data = json.dumps([0, i, name, params]).encode()
    s.sendall(str(len(data)).encode() + b":" + data)
    response = recv(f)
    error = response[2]
    if error and (name != "WebDriver:Navigate" or error["error"] != "timeout"):
        raise RuntimeError(error)
for _ in range(300):
    try:
        s = socket.create_connection(("127.0.0.1", 2828), 2)
        break
    except OSError:
        time.sleep(0.2)
else:
    raise TimeoutError("Firefox did not open the Marionette port")
s.settimeout(15)
f = s.makefile("rb")
recv(f)
send(s, f, 1, "WebDriver:NewSession", {"capabilities": {}})
send(s, f, 2, "WebDriver:SetTimeouts", {"pageLoad": 3000})
url, server_ip, visits = sys.argv[1:]
for i in range(int(visits)):
    if i:
        subprocess.run(["ss", "-K", "dst", server_ip], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        time.sleep(1)
    send(s, f, i + 3, "WebDriver:Navigate", {"url": f"{url}?visit={i}"})
    time.sleep(7)
"""


def firefox_revisits(run, name, url, server_ip, binary, visits=4):
    """Firefox visits a site, then again over new connections: its sockets
    are killed in between and it navigates by Marionette."""
    d = scenario_dir(run, name)
    profile = f"{d}/profile"
    os.makedirs(profile, exist_ok=True)
    sh(f"certutil -d sql:{profile} -N --empty-password && "
       f"certutil -d sql:{profile} -A -t 'C,,' -n standroot -i {S}/certs/real/root.pem")
    with open(f"{profile}/user.js", "w") as f:
        for k, v in {"browser.shell.checkDefaultBrowser": False, "datareporting.policy.dataSubmissionEnabled": False,
                     "toolkit.telemetry.enabled": False, "app.update.enabled": False,
                     "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                     "browser.safebrowsing.malware.enabled": False, "browser.safebrowsing.phishing.enabled": False,
                     "extensions.update.enabled": False, "browser.startup.homepage_override.mstone": "ignore"}.items():
            f.write(f"user_pref({json.dumps(k)}, {json.dumps(v)});\n")
    with open(f"{d}/marionette.py", "w") as f:
        f.write(MARIONETTE)
    cap = Capture(f"{d}/capture.pcap")
    p = start(f"firefox-{name}", f"ip netns exec cli env HOME={d} SSLKEYLOGFILE={d}/keylog MOZ_DISABLE_CONTENT_SANDBOX=1 "
              f"{binary} --headless --no-remote --marionette --profile {profile}", f"{d}/firefox.log")
    subprocess.run(["ip", "netns", "exec", "cli", "python3", f"{d}/marionette.py",
                    url, server_ip, str(visits)], env=ENV, check=True)
    stop(p)
    procs.remove((f"firefox-{name}", p))
    cap.close()
    with open(f"{d}/meta.json", "w") as f:
        json.dump({"kind": "firefox", "binary": binary, "target": url}, f, indent=1)


def run_real(run, sites, xhttp=False):
    real_ips, servers = topology_real(sites)
    inbounds = [{
        "listen": servers[site], "port": 443, "protocol": "vless", "tag": f"in-{site}",
        "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
        "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
            "target": f"{real_ips[site]}:443", "serverNames": [site],
            "privateKey": PRIVATE_KEY, "shortIds": [SHORT_ID], "browser": "auto"}},
    } for site in sites]
    if xhttp:
        for inbound in inbounds:
            inbound["settings"]["decryption"] = VLESS_DECRYPTION
            inbound["streamSettings"].update(
                network="xhttp", xhttpSettings={"path": "/assets/v2", "mode": "auto"})
    with open(f"{run}/server-real.json", "w") as f:
        json.dump({"log": {"loglevel": "warning"}, "inbounds": inbounds,
                   "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}, f, indent=1)
    with open(f"{run}/real.json", "w") as f:
        json.dump({"sites": real_ips, "servers": servers}, f, indent=1)
    start("http", f"python3 -m http.server --bind {HTTP} 80 --directory {S}/www", f"{run}/http.log")
    if xhttp:
        with open(f"{run}/upload_sink.py", "w") as f:
            f.write(UPLOAD_SINK)
        start("upload", f"python3 {run}/upload_sink.py {HTTP}", f"{run}/upload.log")
    start("server-real", f"xray-new run -c {run}/server-real.json", f"{run}/server-real.log")
    time.sleep(45)  # REALITY probes each site, a wrong binder last
    for site in sites:
        chrome_revisits(run, f"chrome-{site}", site, servers[site])
        chrome_revisits(run, f"edge-{site}", site, servers[site], f"{R}/opt/microsoft/msedge/msedge")
        firefox_revisits(run, f"firefox160-{site}", f"https://{site}/", servers[site], FIREFOXES["firefox160"])
        for fp in ("chrome", "firefox", "edge"):
            if xhttp:
                xray_traffic(run, f"xhttp-{fp}-{site}", servers[site], site, fp, "auto", xhttp_client_config)
            else:
                xray_client(run, f"xray-{fp}-{site}", "xray-new", servers[site], site, fp, "auto", 4)


def render():
    """Configs, the page and the stub site, from next to this script."""
    os.makedirs(f"{S}/conf", exist_ok=True)
    os.makedirs(f"{S}/www", exist_ok=True)
    for name in os.listdir(f"{CODE}/conf"):
        with open(f"{CODE}/conf/{name}") as f:
            text = f.read().replace("@WORK@", S)
        with open(f"{S}/conf/{name.removesuffix('.in')}", "w") as f:
            f.write(text)
    shutil.copy(f"{CODE}/www/page.html", f"{S}/www/page.html")
    shutil.copytree(f"{CODE}/stub", f"{S}/stub", dirs_exist_ok=True)


def main():
    render()
    wanted = sys.argv[1:] or ["browsers", "xray"]
    external = wanted[0] in ("real", "real-xhttp")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run = f"{S}/runs/{stamp}"
    os.makedirs(run)
    with open(f"{run}/run.json", "w") as f:
        json.dump({"rtt_ms": 0 if external else int(os.environ.get("RTT_MS", "60")), "args": wanted}, f)
    if external:
        try:
            run_real(run, wanted[1:] or REAL_SITES, xhttp=wanted[0] == "real-xhttp")
        finally:
            stop_all()
        print(run)
        return
    topology()
    try:
        start_targets(run)
        if wanted[0] == "xhttp-h2":
            start_servers(run, old=False)
            for target in wanted[1:] or TARGETS:
                site = PAGE_HOSTS[target]
                chrome_revisits(run, f"chrome-{target}", site, TARGETS[target], cache_bust=True)
                chrome(run, f"fetch-chrome-{target}", target)
                firefox_revisits(run, f"firefox160-{target}", f"https://{site}/", TARGETS[target], FIREFOXES["firefox160"])
                for fp in ("chrome", "firefox"):
                    xray_traffic(run, f"xhttp-{fp}-{target}", XHTTP_SERVER[target], target, fp, "auto", xhttp_client_config)
            print(run)
            return
        if wanted[0] in ("xhttp-off", "xhttp-off-legacy", "xhttp-off-old-client", "xhttp-off-old-both", "xhttp-off-auto-server"):
            server_binary = "xray-old" if wanted[0] in ("xhttp-off-legacy", "xhttp-off-old-both") else "xray-new"
            client_binary = "xray-old" if wanted[0] in ("xhttp-off-old-client", "xhttp-off-old-both") else "xray-new"
            start_servers(run, old=False, browser=wanted[0] == "xhttp-off-auto-server", binary=server_binary)
            for target in wanted[1:] or XHTTP_SERVER:
                browser = "" if client_binary == "xray-old" else "off"
                xray_traffic(run, f"xhttp-off-{target}", XHTTP_SERVER[target], target, "chrome", browser,
                             xhttp_client_config, binary=client_binary)
            print(run)
            return
        if "stub" in wanted or "xhttp" in wanted:
            start_servers(run, old="compat" in wanted or "edge" in wanted)
        if "browsers" in wanted:
            for target in TARGETS:
                chrome(run, f"chrome-{target}", target)
                chrome(run, f"edge-{target}", target, f"{R}/opt/microsoft/msedge/msedge")
                for name, binary in FIREFOXES.items():
                    firefox(run, f"{name}-{target}", target, binary)
        if ("xray" in wanted or "compat" in wanted or "edge" in wanted) and "stub" not in wanted and "xhttp" not in wanted:
            start_servers(run, old="compat" in wanted or "edge" in wanted)
        if "xray" in wanted:
            for target in TARGETS:
                for fp in ("chrome", "firefox", "edge"):
                    xray_client(run, f"xray-{fp}-{target}", "xray-new", NEW_SERVER[target], target, fp, "auto", 4)
                xray_client(run, f"xray-off-{target}", "xray-new", NEW_SERVER[target], target, "chrome", "", 3)
            for fp in ("safari", "ios"):
                xray_client(run, f"xray-{fp}-nginx", "xray-new", NEW_SERVER["nginx"], "nginx", fp, "auto", 3)
        if "stub" in wanted:
            # nginx keeps idle connections 75 s there: new ones come after
            # the browsers' sockets are killed
            for name, binary in (("chrome", None), ("edge", f"{R}/opt/microsoft/msedge/msedge")):
                chrome_revisits(run, f"{name}-stub", "stub.example.test", STUB, binary)
            firefox_revisits(run, "firefox160-stub", "https://stub.example.test/", STUB, FIREFOXES["firefox160"])
            for fp in ("chrome", "firefox", "edge"):
                xray_client(run, f"xray-{fp}-stub", "xray-new", STUB, "stub", fp, "auto", 4)
            ticket_probe(run)
        if "xhttp" in wanted:
            for name, binary in (("chrome", None), ("edge", f"{R}/opt/microsoft/msedge/msedge")):
                chrome_revisits(run, f"{name}-stub", "stub.example.test", STUB, binary)
            firefox_revisits(run, "firefox160-stub", "https://stub.example.test/", STUB, FIREFOXES["firefox160"])
            for target in XHTTP_SERVER:
                for fp in ("chrome", "firefox", "edge"):
                    xray_traffic(run, f"xhttp-{fp}-{target}", XHTTP_SERVER[target], target, fp, "auto", xhttp_client_config)
                xray_traffic(run, f"xhttp-off-{target}", XHTTP_SERVER[target], target, "chrome", "off", xhttp_client_config)
                xray_traffic(run, f"raw-chrome-{target}", NEW_SERVER.get(target, STUB), target, "chrome", "auto")
        if "edge" in wanted:
            # The ticket from the first connection expires during the pause.
            xray_client(run, "edge-expiry", "xray-new", NEW_SERVER["nginxshort"], "nginxshort", "chrome", "auto", 4,
                        pauses=[1, 10, 1, 1])
            lb = start("lb", f"ip netns exec srv haproxy -f {S}/conf/lb.cfg", f"{run}/lb.log")
            wait_port("srv", LB, 443)
            xray_client(run, "edge-mixed-cluster", "xray-new", LB, "nginx", "chrome", "auto", 8)
            stop(lb)
            procs.remove(("lb", lb))
            replay_probe(run, "edge-replay", f"{run}/xray-chrome-nginx" if os.path.isdir(f"{run}/xray-chrome-nginx") else None)
        if "compat" in wanted:
            t = "nginx"
            xray_client(run, "compat-old-client-new-server", "xray-old", NEW_SERVER[t], t, "chrome", "", 3)
            xray_client(run, "compat-new-client-old-server", "xray-new", OLD_SERVER[t], t, "chrome", "auto", 3)
            xray_client(run, "compat-old-client-old-server", "xray-old", OLD_SERVER[t], t, "chrome", "", 3)
    finally:
        stop_all()
    print(run)


if __name__ == "__main__":
    main()

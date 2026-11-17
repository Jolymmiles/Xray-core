#!/usr/bin/env python3
"""analyze.py <run-dir> [scenario...]: what a censor sees of each TLS connection.

For every TCP stream of a scenario's capture: the ClientHello (length,
extension types in order, PSK identity lengths, JA4), and the records in
order with direction, length on the wire and, decrypted with the keylog
where it can be, the handshake messages inside. Writes analysis.json next
to the capture and prints a summary.
"""
import json
import os
import subprocess
import sys

S = os.environ.get("STAND_WORK") or os.path.expanduser("~/.cache/realitystand")
CODE = os.path.dirname(os.path.abspath(__file__))
R = S + "/root"
ENV = dict(os.environ)
ENV["PATH"] = f"{R}/usr/bin:" + ENV.get("PATH", "")
ENV["LD_LIBRARY_PATH"] = f"{R}/usr/lib/x86_64-linux-gnu:{R}/lib/x86_64-linux-gnu"

# ClientHello fields compared value by value.
HELLO_FIELDS = {
    "ciphers": "tls.handshake.ciphersuite",
    "groups": "tls.handshake.extensions_supported_group",
    "key_shares": "tls.handshake.extensions_key_share_group",
    "key_share_lens": "tls.handshake.extensions_key_share_key_exchange_length",
    "sig_algs": "tls.handshake.sig_hash_alg",
    "versions": "tls.handshake.extensions.supported_version",
    "alpn": "tls.handshake.extensions_alpn_str",
    "cert_compression": "tls.compress_certificate.algorithm",
    "psk_modes": "tls.extension.psk_ke_mode",
    "record_size_limit": "tls.record_size_limit",
    "point_formats": "tls.handshake.extensions_ec_point_format",
    "status_request": "tls.handshake.extensions_status_request_type",
    "session_id_len": "tls.handshake.session_id_length",
    "compression": "tls.handshake.comp_method",
}
HS = {1: "CH", 2: "SH", 4: "NST", 8: "EE", 11: "Cert", 13: "CR", 15: "CV", 20: "Fin", 24: "KU", 25: "CompCert"}
CT = {20: "CCS", 21: "Alert", 22: "HS", 23: "App"}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def walk(layer, key):
    """All values of key anywhere under layer."""
    out = []
    if isinstance(layer, dict):
        for k, v in layer.items():
            if k == key:
                out.extend(as_list(v))
            out.extend(walk(v, key))
    elif isinstance(layer, list):
        for v in layer:
            out.extend(walk(v, key))
    return out


def records_of(tls):
    """The tls.record entries of a frame's tls layer, in order."""
    recs = []
    for part in as_list(tls):
        if isinstance(part, dict):
            for k, v in part.items():
                if k == "tls.record":
                    recs.extend(as_list(v))
    return recs


def h2_startup(chunks):
    """Server record lengths and control frame order through SETTINGS ACK."""
    before, lengths, controls = [], [], []
    for records, frames in chunks:
        if not controls and "SETTINGS" not in frames:
            before.extend(records)
            continue
        if not records:
            return None
        lengths.extend(records)
        controls.extend(frame for frame in frames if frame in ("SETTINGS", "WINDOW_UPDATE", "ACK"))
        if "ACK" in frames:
            return {"lengths": lengths, "controls": controls, "before": before}
    return None


def h2_frames(layer):
    for part in as_list(layer):
        for frame in as_list(part.get("http2.stream")):
            kind = frame.get("http2.type")
            if kind == "4":
                yield "ACK" if int(frame["http2.flags"], 0) & 1 else "SETTINGS"
            elif kind == "8" and frame.get("http2.streamid") == "0":
                yield "WINDOW_UPDATE"
            else:
                yield kind


def analyze(scenario_dir):
    pcap = f"{scenario_dir}/capture.pcap"
    keylog = f"{scenario_dir}/keylog"
    cmd = ["tshark", "-r", pcap, "-T", "json", "--no-duplicate-keys", "-Y", "tls", "-J", "frame tcp tls http2 ip"]
    if os.path.exists(keylog):
        cmd[3:3] = ["-o", f"tls.keylog_file:{keylog}"]
    out = subprocess.run(cmd, env=ENV, capture_output=True, text=True, check=True).stdout
    frames = json.loads(out)
    streams = {}
    for fr in frames:
        layers = fr["_source"]["layers"]
        tcp = layers.get("tcp", {})
        stream = int(tcp.get("tcp.stream", -1))
        sport = int(tcp.get("tcp.srcport", 0))
        direction = "s>c" if sport == 443 else "c>s"
        t = float(layers.get("frame", {}).get("frame.time_relative", 0) or 0)
        st = streams.setdefault(stream, {"stream": stream, "records": [], "ch": None,
                                         "server_psk_selected": None, "h2_chunks": []})
        h2_records = []
        for rec in records_of(layers.get("tls")):
            if not isinstance(rec, dict):
                continue
            ctype = int(rec.get("tls.record.content_type", rec.get("tls.record.opaque_type", 0)) or 0)
            length = int(rec.get("tls.record.length", 0) or 0) + 5
            hs_types = [HS.get(int(x), str(x)) for x in walk(rec, "tls.handshake.type")]
            item = {"dir": direction, "len": length, "type": CT.get(ctype, str(ctype))}
            if hs_types:
                item["hs"] = hs_types
            st["records"].append(item)
            item["t"] = round(t, 4)
            if direction == "s>c":
                if "SH" in hs_types:
                    st["server_psk_selected"] = bool(walk(rec, "tls.handshake.extensions.psk.identity.selected"))
                if rec.get("tls.app_data_proto") == "HyperText Transfer Protocol 2":
                    h2_records.append(length)
            if "CH" in hs_types and st["ch"] is None:
                exts = [int(x) for x in walk(rec, "tls.handshake.extension.type")]
                st["ch"] = {
                    "t": round(t, 3),
                    "len": int(walk(rec, "tls.handshake.length")[0]) if walk(rec, "tls.handshake.length") else 0,
                    "sni": (walk(rec, "tls.handshake.extensions_server_name") or [""])[0],
                    "exts": exts,
                    "psk_identities": [int(x) for x in walk(rec, "tls.handshake.extensions.psk.identity.identity_length")],
                    "ja4": (walk(rec, "tls.handshake.ja4") or [""])[0],
                    # length of each extension, in order with exts
                    "ext_lens": [int(x) for x in walk(rec, "tls.handshake.extension.len")],
                    "detail": {name: [str(v) for v in walk(rec, field)] for name, field in HELLO_FIELDS.items()},
                }
        if direction == "s>c" and (h2_records or "http2" in layers):
            st["h2_chunks"].append((h2_records, list(h2_frames(layers.get("http2")))))
    for st in streams.values():
        st["timing"] = timing(st["records"])
        st["h2_startup"] = h2_startup(st.pop("h2_chunks"))
    result = [streams[k] for k in sorted(streams)]
    with open(f"{scenario_dir}/analysis.json", "w") as f:
        json.dump(result, f, indent=1)
    return result


def timing(records):
    """Milliseconds from the ClientHello to: the ServerHello, the client's
    Finished, the first ticket, the client's first data and the server's."""
    def first(pred):
        for r in records:
            if pred(r):
                return r["t"]
        return None
    t0 = first(lambda r: "CH" in r.get("hs", []))
    marks = {
        "sh": first(lambda r: "SH" in r.get("hs", [])),
        "client_fin": first(lambda r: r["dir"] == "c>s" and "Fin" in r.get("hs", [])),
        "nst": first(lambda r: "NST" in r.get("hs", [])),
        "client_data": first(lambda r: r["dir"] == "c>s" and r["type"] == "App" and not r.get("hs")),
        "server_data": first(lambda r: r["dir"] == "s>c" and r["type"] == "App" and not r.get("hs")),
    }
    if t0 is None:
        return {}
    return {k: round((v - t0) * 1000, 1) for k, v in marks.items() if v is not None}


def short(records, limit=12):
    parts = []
    for r in records[:limit]:
        tag = "+".join(r.get("hs", [])) or r["type"]
        parts.append(f"{'>' if r['dir'] == 'c>s' else '<'}{tag}:{r['len']}")
    return " ".join(parts)


def main():
    run = sys.argv[1]
    names = sys.argv[2:] or sorted(d for d in os.listdir(run) if os.path.isdir(f"{run}/{d}"))
    for name in names:
        d = f"{run}/{name}"
        if not os.path.exists(f"{d}/capture.pcap"):
            continue
        print(f"== {name}")
        for st in analyze(d):
            ch = st["ch"] or {}
            psk = ch.get("psk_identities") or "-"
            print(f"  #{st['stream']} t={ch.get('t')} CH {ch.get('len')} exts={len(ch.get('exts', []))} psk={psk} {ch.get('ja4', '')}")
            print(f"     {short(st['records'])}")
            print(f"     ms {st['timing']}")


if __name__ == "__main__":
    main()

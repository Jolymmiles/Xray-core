#!/usr/bin/env python3
"""compare.py [--xhttp | --xhttp-off] <reference-run> <xray-run>: compare captures.

For each target and browser, the browser's connections straight to the
target (reference) against the Xray client's through REALITY (ours), on what
a censor sees and what the keylog adds:

  hello      ClientHello extensions: the set for Chrome, which shuffles them,
             the order for Firefox; with a ticket and without
  psk        length of the PSK identity
  full       server records of a full handshake: types and lengths, from
             ServerHello to the last ticket
  resumed    the same for a resumed handshake
  tickets    tickets after a full and after a resumed handshake

Lengths of CertificateVerify differ by a byte or two between handshakes
(ECDSA signatures), so they are compared within 2 bytes.
"""
import json
import os
import subprocess
import sys

S = os.environ.get("STAND_WORK") or os.path.expanduser("~/.cache/realitystand")
CODE = os.path.dirname(os.path.abspath(__file__))
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}
HANDSHAKE_TAGS = {"SH", "CCS", "EE", "Cert", "CV", "Fin", "NST"}


def load(run, name):
    path = f"{run}/{name}/analysis.json"
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        if all("server_psk_selected" in stream and "h2_startup" in stream
               and "h2_started" in stream
               and (not stream["h2_startup"] or "before" in stream["h2_startup"]) for stream in data):
            return data
    if not os.path.isfile(f"{run}/{name}/capture.pcap"):
        raise ValueError(f"{run}/{name}: current analysis or raw capture required")
    subprocess.run([sys.executable, f"{CODE}/analyze.py", run, name], stdout=subprocess.DEVNULL, check=True)
    with open(path) as f:
        return json.load(f)


def tag(r):
    # A compressed certificate goes where the certificate does: REALITY
    # sends its own in a record as long, which a censor cannot tell apart.
    return "+".join("Cert" if t == "CompCert" else t for t in r.get("hs", [])) or r["type"]


def server_shape(stream):
    """Server records from ServerHello through the last ticket."""
    recs = [r for r in stream["records"] if r["dir"] == "s>c"]
    shape = []
    for r in recs:
        t = tag(r)
        if not set(t.split("+")) <= HANDSHAKE_TAGS:
            if any(x == "NST" for s in shape for x in s[0].split("+")) or t == "App":
                # an App record ends the handshake once the flight is done
                if any("Fin" in s[0] for s in shape):
                    break
            continue
        shape.append((t, r["len"]))
    return shape


def tickets(shape):
    return sum(t.split("+").count("NST") for t, _ in shape)


def ext_key(exts, ordered):
    exts = [e for e in exts if e not in GREASE]
    return exts if ordered else sorted(exts)


def norm(v):
    """GREASE values compare equal to each other."""
    try:
        n = int(v, 0) if isinstance(v, str) else int(v)
    except ValueError:
        return v
    return "GREASE" if n in GREASE else n


# Extensions whose length a browser picks at random per connection: their
# lengths are compared as the sets seen over all connections instead.
RANDOM_LEN = {"chrome": {0xfe0d}, "edge": {0xfe0d}}
# The lengths Chromium picks its GREASE ECH from (BoringSSL, uniformly).
KNOWN_LENS = {0xfe0d: {186, 218, 250, 282}}


def hello_diff(ref, ours, skip=()):
    """Differences in content between two ClientHellos: each field value by
    value, in order, and the lengths of each extension type."""
    diffs = []
    for field, a in ref.get("detail", {}).items():
        b = ours.get("detail", {}).get(field, [])
        a, b = [norm(x) for x in a], [norm(x) for x in b]
        if a != b:
            diffs.append(f"{field}: ref {a} ours {b}")
    lens = []
    for ch in (ref, ours):
        d = {}
        for t, l in zip(ch["exts"], ch.get("ext_lens", [])):
            d.setdefault(norm(t), []).append(l)
        lens.append(d)
    for t in sorted(set(lens[0]) | set(lens[1]), key=str):
        if t in skip:
            continue
        if sorted(lens[0].get(t, [])) != sorted(lens[1].get(t, [])):
            diffs.append(f"ext {t} len: ref {lens[0].get(t)} ours {lens[1].get(t)}")
    return diffs


def same_shape(a, b):
    if len(a) != len(b):
        return False
    for (ta, la), (tb, lb) in zip(a, b):
        if ta != tb:
            return False
        if abs(la - lb) > (2 if "CV" in ta.split("+") else 0):
            return False
    return True


def split(streams):
    full = [s for s in streams if s["ch"] and s["server_psk_selected"] is False]
    res = [s for s in streams if s["ch"] and s["server_psk_selected"] is True]
    return full, res


def fmt(shape):
    return " ".join(f"{t}:{l}" for t, l in shape)


def compare_handshakes(label, reference, candidates, browser):
    expected = []
    for stream in reference:
        shape = server_shape(stream)
        if any("Fin" in tag.split("+") for tag, _ in shape):
            expected.append((stream["ch"], shape))
    if not expected or not candidates:
        return [(label, False, f"handshakes: complete ref {len(expected)}, ours {len(candidates)}")]
    if label == "full":
        # A reference connection can close before its tickets arrive.
        issued = max(tickets(shape) for _, shape in expected)
        expected = [(ch, shape) for ch, shape in expected if tickets(shape) == issued]

    ordered = browser == "firefox"
    skip = RANDOM_LEN.get(browser, ())
    checks = []
    for candidate in candidates:
        hello = candidate["ch"]
        shape = server_shape(candidate)
        differences = []
        for ref_hello, ref_shape in expected:
            errors = hello_diff(ref_hello, hello, skip)
            if ext_key(ref_hello["exts"], ordered) != ext_key(hello["exts"], ordered):
                errors.append(f"extensions: ref {ref_hello['exts']} ours {hello['exts']}")
            if ref_hello["psk_identities"] != hello["psk_identities"]:
                errors.append(f"PSK lengths: ref {ref_hello['psk_identities']} ours {hello['psk_identities']}")
            if not same_shape(ref_shape, shape):
                errors.append(f"records: ref {fmt(ref_shape)} ours {fmt(shape)}")
            if not errors:
                break
            differences.append(errors)
        else:
            checks.append((label, False, f"stream {candidate['stream']}: " + "; ".join(min(differences, key=len))))
    return checks or [(label, True, "")]


def compare(ref_run, our_run, browser, target, ref_name=None):
    ref = load(ref_run, f"{ref_name or browser}-{target}")
    ours = load(our_run, f"xray-{browser}-{target}")
    rf, rr = split(ref)
    of, orr = split(ours)
    checks = compare_handshakes("full", rf, of, browser)

    def check(name, ok, detail):
        checks.append((name, ok, detail))

    for t in RANDOM_LEN.get(browser, ()):
        seen = []
        # all of the browser's connections in the reference run, any target
        every = [st for d in sorted(os.listdir(ref_run)) if d.startswith(f"{ref_name or browser}-")
                 for st in load(ref_run, d)]
        for streams in (every, ours):
            seen.append(sorted({l for s in streams if s["ch"] for e, l in zip(s["ch"]["exts"], s["ch"]["ext_lens"]) if e == t}))
        check(f"ext {t} lens", set(seen[1]) <= set(seen[0]) | KNOWN_LENS.get(t, set()),
              f"ref {seen[0]} ours {seen[1]}")
    # Time from the ServerHello to the client's Finished of full handshakes,
    # over that of resumed ones: the browser verifying the certificate.
    def verify_ms(streams):
        timed = [s for s in streams if "client_fin" in s.get("timing", {}) and "sh" in s["timing"]]
        full_streams, resumed_streams = split(timed)
        full = [s["timing"]["client_fin"] - s["timing"]["sh"] for s in full_streams]
        res = sorted(s["timing"]["client_fin"] - s["timing"]["sh"] for s in resumed_streams)
        if not full or not res:
            return None
        base = res[len(res) // 2]
        return [round(f - base, 1) for f in full]
    a = [x for d in sorted(os.listdir(ref_run)) if d.startswith(f"{ref_name or browser}-")
         for x in (verify_ms(load(ref_run, d)) or [])]
    b = verify_ms(ours)
    if a and b:
        # A browser's first verification after it starts is slow (125 ms
        # for a real chain here), later ones are not: ours only has to fall
        # in the range.
        check("verify delay", min(a) - 10 <= min(b) and max(b) <= max(a) + 10, f"ref {a} ours {b} ms")
    if rr or orr:
        checks.extend(compare_handshakes("resumed", rr, orr, browser))
    else:
        check("resumed", True, "neither resumes")  # a target that refuses its tickets
    return checks


PAIRS = (("chrome", "chrome"), ("edge", "edge"), ("firefox", "firefox156"), ("firefox", "firefox160"))
XHTTP_PAIRS = (("chrome", "chrome"), ("firefox", "firefox160"))


def compare_h2(ref, ours, off=False):
    """Compare each accepted handshake class to the observed reference variants."""
    def startup(stream):
        h2 = stream["h2_startup"]
        if not h2:
            return None
        return h2 if off else {key: h2[key] for key in ("lengths", "controls")}

    checks = []
    if off:
        offered = any((stream["ch"] or {}).get("psk_identities") for stream in (*ref, *ours))
        checks.append(("PSK offer", not offered, "browser-off ClientHello offered PSK"))
    for label, reference, candidate in zip(("full", "resumed"), split(ref), split(ours)):
        expected = [startup(s) for s in reference if s["h2_startup"]]
        observed = [startup(s) for s in candidate if s["h2_startup"]]
        if off and label == "resumed" and (reference or candidate):
            checks.append(("H2 resumed", False, "unexpected resumption in browser-off capture"))
            continue
        if label == "resumed" and not reference and not candidate:
            continue
        incomplete = [s["stream"] for s in candidate if not s["h2_startup"]
                      and (s.get("h2_started") or "client_fin" in s.get("timing", {}))]
        if incomplete:
            checks.append((f"H2 {label}", False, f"incomplete or ambiguous startups in streams {incomplete}"))
        if not expected or not observed:
            checks.append((f"H2 {label}", False, f"complete H2 startups: ref {len(expected)}, ours {len(observed)}"))
            continue
        unexpected = [s for s in observed if s not in expected]
        checks.append((f"H2 {label}", not unexpected, f"ref {expected}, unexpected {unexpected}"))
    return checks


def compare_xhttp(ref_run, our_run, off=False):
    pairs = (("off", "xhttp-off"),) if off else XHTTP_PAIRS
    targets = set()
    for run, prefixes in ((ref_run, [f"{browser}-" for _, browser in pairs]),
                          (our_run, [f"xhttp-{fp}-" for fp, _ in pairs])):
        for name in os.listdir(run):
            for prefix in prefixes:
                if name.startswith(prefix):
                    targets.add(name.removeprefix(prefix))
    if not targets:
        print("DIFF no XHTTP captures")
        return 1
    failed = 0
    for target in sorted(targets):
        for fp, browser in pairs:
            ref_name, our_name = f"{browser}-{target}", f"xhttp-{fp}-{target}"
            reference = our_run if target == "stub" and not off else ref_run
            print(f"== XHTTP {fp} via {target}, reference {browser}")
            if not os.path.isdir(f"{reference}/{ref_name}") or not os.path.isdir(f"{our_run}/{our_name}"):
                print(f"  DIFF need {ref_name} and {our_name}")
                failed += 1
                continue
            expected = load(reference, ref_name)
            fetch_ref = f"fetch-{ref_name}"
            if fp == "chrome" and os.path.isdir(f"{reference}/{fetch_ref}"):
                expected += load(reference, fetch_ref)
            for name, ok, detail in compare_h2(expected, load(our_run, our_name), off):
                failed += not ok
                print(f"  {'ok  ' if ok else 'DIFF'} {name:14s}" + (f" {detail}" if not ok else ""))
    print(f"{failed} XHTTP differences")
    return int(failed > 0)


def main():
    """Exits 1 when anything differs, or a reference has no capture of ours."""
    if len(sys.argv) == 4 and sys.argv[1] in ("--xhttp", "--xhttp-off"):
        sys.exit(compare_xhttp(*sys.argv[2:], off=sys.argv[1] == "--xhttp-off"))
    ref_run, our_run = sys.argv[1], sys.argv[2]
    failed = 0
    targets = set()
    for run, prefixes in ((ref_run, {r for _, r in PAIRS}), (our_run, {f"xray-{b}" for b, _ in PAIRS})):
        for d in os.listdir(run):
            for prefix in prefixes:
                if d.startswith(prefix + "-"):
                    targets.add(d[len(prefix) + 1:])
    checked = 0
    for target in sorted(targets):
        for browser in {browser for browser, _ in PAIRS}:
            if os.path.isdir(f"{our_run}/xray-{browser}-{target}") and not any(
                os.path.isdir(f"{ref_run}/{name}-{target}") for fp, name in PAIRS if fp == browser
            ):
                failed += 1
                print(f"  DIFF {'capture':14s} no {browser} reference for {target} in {ref_run}")
        for browser, ref_name in PAIRS:
            if not os.path.isdir(f"{ref_run}/{ref_name}-{target}"):
                continue
            checked += 1
            print(f"== {browser} via {target}, reference {ref_name}")
            if not os.path.isdir(f"{our_run}/xray-{browser}-{target}"):
                failed += 1
                print(f"  DIFF {'capture':14s} no xray-{browser}-{target} in {our_run}")
                continue
            for name, ok, detail in compare(ref_run, our_run, browser, target, ref_name):
                failed += not ok
                print(f"  {'ok  ' if ok else 'DIFF'} {name:14s}" + (f" {detail}" if detail and not ok else ""))
    if not checked:
        print("DIFF no browser reference captures")
        failed += 1
    print(f"{failed} differences")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

# REALITY session resumption stand

Checks that REALITY with `"browser": "auto"` looks, on the wire, like a
browser talking to the target: the ClientHello with and without a ticket,
the server's records of full and resumed handshakes, and the initial
HTTP/2 records for XHTTP. Runs without root, in user and network namespaces.

```
cli 10.9.0.1 --veth (netem, 60 ms RTT)-- srv
                                          .11 nginx (OpenSSL)   .12 Caddy (crypto/tls)   .13 HAProxy (OpenSSL)
                                          .14 nginx, tickets live 8 s
                                          .15 Angie, reverse proxy to .50
                                          .16 Envoy, reverse proxy to .50
                                          .21-.24 REALITY, new build      .31-.33 REALITY, old build
                                          .25-.27 XHTTP over REALITY to nginx, Caddy and HAProxy
                                          .28 XHTTP and .29 RAW over REALITY to Angie
                                          .30 XHTTP and .34 RAW over REALITY to Envoy
                                          .40 HAProxy TCP round robin over .21 and .31
                                          .50 plain HTTP behind the proxies
                                          .60 REALITY and .62 XHTTP in front of the stub
```

The capture is taken on the client's side of the veth: what a censor sees.
The clients write their TLS secrets, so the captures decrypt.

## Setup

```sh
testing/realitystand/setup.sh . <new-ref> <old-ref>
```

Everything lands in `$STAND_WORK` (default `~/.cache/realitystand`):
Debian packages unpacked under `root/` (`install.sh`), Google Chrome stable,
Caddy checked against its release checksums, a copy of tcpdump (the system
one has an AppArmor profile that refuses signals and writes to hidden
directories), a test CA, and `xray-new`/`xray-old` built from the two refs.
Native runs use the system Firefox for the `firefox` scenario. Before
running the full `browsers` group, install Edge under
`$STAND_WORK/root/opt/microsoft/msedge/` and extract Firefox 156.0.1 and
160.0 under `$STAND_WORK/root/opt/firefox-156.0.1/` and
`$STAND_WORK/root/opt/firefox-160.0/`, respectively. Angie and Envoy are
included when their binaries are on the stand's PATH.

### Docker Desktop

Use Linux amd64 containers. Build the image with the stand's archive directory
as a named build context. It needs `chrome.deb`, `edge.deb`, both Firefox
tarballs and the Caddy archive and checksum file used by the Linux stand.

```powershell
$archives = 'C:/path/to/stand/dl'
docker build --build-context "archives=$archives" -t xray-realitystand:local ./testing/realitystand
```

Create a container and copy in the Linux amd64 Xray binaries. The
`http2legacy` build tag matches the native stand. `compat` and `edge`
also use `xray-old`.

```powershell
docker create --name realitystand-local --init --network none --shm-size 512m `
  --cap-add NET_ADMIN --cap-add SYS_ADMIN `
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined `
  --entrypoint sh xray-realitystand:local -ec 'chmod +x /stand/bin/xray-*; exec python3 /opt/realitystand/stand.py browsers xhttp'
docker cp C:/path/to/xray-new realitystand-local:/stand/bin/xray-new
docker cp C:/path/to/xray-old realitystand-local:/stand/bin/xray-old
docker start -a realitystand-local
docker cp realitystand-local:/stand/runs ./realitystand-runs
```

The container runs both network namespaces and applies netem to the veth
interfaces. Use `-e RTT_MS=0` if the Docker kernel lacks netem. For an
external-target run, create the container with `--network bridge` and use
`real-xhttp www.cloudflare.com` or `real www.cloudflare.com` as the stand
arguments. The outer Docker namespace supplies network access. The
Dockerfile fetches Angie from its signed Debian repository and Envoy from
its official image.

## Run

```sh
cd testing/realitystand
unshare -Urnm python3 stand.py browsers xray compat edge stub xhttp  # RTT_MS=60 by default
python3 analyze.py <run-dir>                                 # per connection
python3 compare.py <run-with-browsers> <run-with-xray>       # browsers vs REALITY
```

Each scenario leaves `capture.pcap`, `keylog`, `meta.json`, `analysis.json`
and the logs in `runs/<stamp>/<scenario>/`.

| group | scenarios |
|---|---|
| `browsers` | Chrome, Edge and Firefox straight to each target: a page fetches again after the target closes the idle connection |
| `xray` | the new client through the new server, `chrome` and `firefox` fingerprints with `browser: auto`, and `chrome` without |
| `compat` | old client and new server, new client and old server, old with old |
| `edge` | ticket expiry; a new and an old server behind one address; a censor replaying a ClientHello that offers a ticket |
| `stub` | browsers and Xray clients through REALITY in front of the stub, plus a ticket probe with a wrong binder |
| `xhttp` | downloads, uploads and small requests over XHTTP with REALITY and VLESS encryption, with RAW captures for comparison |
| `real` | browser revisits and Xray through REALITY in front of external sites, using the command below |
| `real-xhttp` | browser references and XHTTP traffic with REALITY and VLESS encryption in front of external sites |

```sh
. ./env.sh
pasta --config-net -q -- unshare -m python3 stand.py real www.microsoft.com ya.ru
```

`compare.py` checks, per target and browser: ClientHello extensions (the set
for Chrome, which shuffles them, the order for Firefox), PSK identity length,
and the server records of full and resumed handshakes by type and length
(CertificateVerify within 2 bytes).
The HTTP/2 comparison reports an incomplete capture if tshark cannot
associate SETTINGS or its ACK with a single TLS record in a packet.

## XHTTP startup records

Set `"browser": "auto"` in the inbound and outbound
`realitySettings` to enable browser behavior. With the inbound option
omitted or set to `"off"`, the server runs the original REALITY record
probes. Ticket and HTTP/2 startup probes are enabled by the inbound
option. On an enabled inbound, a client without browser mode follows
the original per-connection path, including the original post-handshake
records and HTTP/2 startup.

The enabled inbound makes background TLS probes for each target, server
name and ALPN profile. For HTTP/2 it also measures startup with a
`GET /` request. See [replay protection and ticket refusal](#replay-protection-and-ticket-refusal)
for its scope.

Xray in this branch uses Joly's baseline uTLS presets. The modern
browser captures also serve as reference data for the separate uTLS
preset update. In particular, the baseline Firefox preset uses full
handshakes when it cannot offer a ticket.

Capture Chrome and Firefox navigating to the target URL used for the
probes. The Chrome references also include a page that performs
successive fetches after the idle timeout. Compare the resulting variants
with the XHTTP captures:

```sh
unshare -Urnm python3 stand.py xhttp-h2 nginx caddy haproxy
python3 compare.py --xhttp <run> <run>
```

The check compares the sequence of TLS wire lengths and HTTP/2 control
frame order through the server's SETTINGS ACK. It compares full and
resumed handshakes separately, using the accepted PSK in ServerHello.
Each observed startup must match a reference startup for that handshake.
It reports missing samples and returns a nonzero status on differences.
The `xhttp-off-<target>` captures exercise a client with browser mode off
against the same enabled inbound.

For an A/B run with browser mode omitted on the server, use the same
client build against the old and new servers:

```sh
unshare -Urnm python3 stand.py xhttp-off-legacy nginx
unshare -Urnm python3 stand.py xhttp-off nginx
python3 compare.py --xhttp-off <legacy-run> <current-run>
```

`xhttp-off-legacy` runs the current client against the old server.
`xhttp-off-old-client` runs the old client against the current server.
Compare the latter with `xhttp-off-old-both` to keep the client build
fixed across runs. Use `xhttp-off-auto-server` to check that the
current server also preserves the startup of an off client when the
inbound enables browser mode. Compare that run with `xhttp-off-legacy`.

To inspect the decoded records using the scenario's key log:

```sh
scenario=<run-dir>/xhttp-chrome-caddy
tshark -r "$scenario/capture.pcap" -o "tls.keylog_file:$scenario/keylog" \
  -Y 'tcp.srcport == 443 && http2' -T fields \
  -e tcp.stream -e tls.record.length -e http2.type -e http2.flags
```

Add 5 to `tls.record.length` for the wire length. Check by TCP stream,
choosing connections that exchanged a SETTINGS ACK. The reference
captures include these server control records, before HTTP response data:

| Target | TLS wire lengths | HTTP/2 frames |
|---|---|---|
| nginx and Angie | 62, 31 | SETTINGS + WINDOW_UPDATE, then ACK |
| Caddy | 67, 35, 31 or 67, 44 | SETTINGS, then separate or combined WINDOW_UPDATE and ACK |
| HAProxy | 58 | SETTINGS + ACK |
| Envoy | 77 | SETTINGS + ACK + WINDOW_UPDATE |

The XHTTP server probes the target with an HTTP/2 preface and reuses the
observed grouping. If the target starts at the default connection window,
XHTTP defers its extra upload credit until request data flows. With
`h2Flow` enabled on a shaped connection, its tagged PING starts with the
first HTTP response.

REALITY probes the target with the preface sent immediately and after 60 ms,
on a full connection and again with a ticket from that connection. In the
Docker runs, nginx and Cloudflare grouped SETTINGS, WINDOW_UPDATE and ACK
into 71 bytes with an immediate preface, and split them into 62 and 31
bytes with the delay. Caddy switched between 67 + 44 and 67 + 35 + 31.
HAProxy sent 58 bytes in both cases.

REALITY also sends a `GET /` with the preface, advertises the browsers'
64 KiB HPACK table, and stops reading once the server's SETTINGS ACK
arrives. If the target
combines startup controls and response headers, XHTTP can use that record
for its controls and as much of its own response as fits. Chromium full
handshakes use a delayed preface sample to capture SETTINGS arriving
before the combined ACK and response. Firefox can use a sample that
combines the greeting into one record, with or without a response.
Resumed Chromium prefers the
immediate control-only sample. If the response does not arrive in time,
XHTTP releases the controls. The response portion of a record can vary
with the URL, headers, and target response. The profile is refreshed in the background when it is an hour
old. When no profile is available, it passes the HTTP/2 frame sequence
through.

Individual browser connections to a target can use either grouping. Compare each
handshake type using the selected PSK identity in ServerHello. An offer
in ClientHello also appears when the target declines to resume.

## Findings (2026-11-16)

References: Chrome 157, Edge 157, Firefox 156.0.1 and 160.0 (Firefox 153 ESR
of the system too), straight to each target. With the changes below,
`compare.py` finds no difference for chrome, edge and firefox through
REALITY: ClientHello content (every field and every extension's length;
GREASE ECH lengths as sets for Chromium, which picks them at random), PSK
identity length, the server's records of full and resumed handshakes, and
the time the client takes for its Finished.

- Firefox drops `session_ticket` when it offers a ticket and grows its
  GREASE ECH payload by the size of `pre_shared_key` rounded up to 32
  bytes; Chrome and Edge keep `session_ticket` and pick ECH lengths from
  {186, 218, 250, 282} regardless.
- Edge 157 is Chrome 155's ClientHello without `trust_anchors`; uTLS's
  `edge` was Edge 85, with no ML-KEM key share, which REALITY servers
  refuse. `ios` was iOS 14, also refused; it is now Safari 26.3's, which
  JA4 databases show for current macOS Safari and, at each version, the
  same for iOS.
- Safari's ClientHello (26.3) matches the most common Safari 27 JA4
  (`t13d2013h2_a09f3c656075_7f0f34a4126d`). No Safari JA4 seen in the wild
  is that ClientHello with `pre_shared_key`, so `safari` and `ios` do not
  resume.
- Browsers send their Finished later in full handshakes, verifying the
  certificate chain: Chrome 8-18 ms, Edge 7-10 ms, Firefox 1-5 ms over
  resumed ones (this 4-core machine). The client now waits as long after
  verifying REALITY's certificate.
- Old and new clients and servers work together in every combination.
- Behind one address with an old server, a ticket that reaches the old one
  ends in the target's certificate and a dropped connection; the client then
  offers no ticket there for 10 minutes.

### Replay protection and ticket refusal

The server records authenticated browser-mode ClientHellos with a valid
ticket and binder before it starts a REALITY handshake. A repeated
ClientHello goes to the target. The bounded history holds up to 40,000 entries per
process in one process-wide cache, shared by all inbounds. Protection
for an entry ends when it expires, is evicted, or the process restarts.
Independent replicas have independent histories. The `edge` group
captures the replay scenario.

For an invalid binder, the probe distinguishes a TLS alert, a closed
read side, a reset, and a read deadline with no response. Silence must
be observed twice before it is stored. A TCP reset
can be reproduced on a connection that exposes its underlying TCP
socket. The delay is measured at the target and includes network jitter.

## Not covered yet

- XHTTP startup records against other external targets besides Cloudflare.
- mihomo and sing-box clients.
- A target that restarts with a new ticket key (the server probes again
  hourly).

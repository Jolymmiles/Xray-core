# H2MUX clean-room design

## Scope

Xray accepts explicit `smux.protocol: "h2mux"` for outbound carriers and
auto-detects H2MUX carriers on the existing inbound destination
`sp.mux.sing-box.arpa:444`. The existing empty/default protocol remains
`smux`. YAMUX remains unsupported.

H2MUX reuses the existing stream request, response, TCP, UDP, packet-address,
padding, retry, pool, and outbound Brutal exchange code. Xray has no inbound
SMUX bandwidth configuration, so this change does not add server-side Brutal
configuration.

## Clean-room boundary

Production code is independently implemented from this document, Xray's
existing in-tree framing, the public HTTP/2 specification, the public
`golang.org/x/net/http2` API, and black-box process captures from sing-box and
Mihomo. GPL mux source is excluded and remains only an external executable
compatibility peer.

## Wire and ownership

The carrier request keeps the existing version and optional-padding encoding;
protocol byte `2` selects H2MUX. After that request, HTTP/2 prior knowledge runs
directly over the authenticated carrier. Each logical connection is one HTTP
CONNECT exchange. HTTP status 200 establishes the logical byte stream; the
existing sing-mux stream request and response bytes are carried in HTTP/2 DATA.

One small internal client-session interface lets the existing pool own either
an MPL SMUX session or an HTTP/2 client connection. The inbound service selects
the MPL accept loop or an HTTP/2 `ServeConn` handler from the carrier protocol.
The H2 handler publishes a stream only after writing HTTP 200, serializes and
flushes response writes, and closes request/response resources on cancellation.

## Acceptance gates

- Config accepts `smux` and `h2mux`, while blank remains `smux`.
- Carrier codec accepts only protocol bytes 0 and 2, including v1/no-padding.
- In-process TCP and UDP round trips pass in both client/server directions.
- Padding and outbound Brutal use the same shared paths under H2MUX.
- Cancellation and carrier teardown leave no blocked stream handlers.
- Unit, race, dependency-ban, process interoperability, and Linux build gates
  pass. Process peers are started separately; no GPL implementation is linked.

# Xray sing-mux wire protocol

This package implements the sing-mux compatible SMUX and H2MUX wire protocols
without a runtime dependency on sing-mux or another multiplexing library.

All multi-byte integers in the outer protocol are unsigned and big endian.
The embedded SMUX v1 carrier is specified in `ENGINE_SPEC.md`; its integers are
little endian as required for interoperability.

## Carrier request

The carrier is a TCP connection to `sp.mux.sing-box.arpa:444`.

* Version 0: `version(1) protocol(1)`. Protocol 0 is SMUX and protocol 2 is
  H2MUX.
* Version 1: `version(1) protocol(1) padding(1) padding_length(2) padding(N)`.

### Version 2 negotiated carrier

Version 2 is Xray-specific and is sent only when `logicalHalfClose` is `auto` or
`require`: `version(1)=2 protocol(1)=0 flags(1) reserved(1)
offered_features(4) nonce(16) padding_length(2) padding(N)`. Flag bit 0 marks
padding and feature bit 0 offers logical half-close. The server replies before
padding or SMUX framing with `version(1)=2 status(1) reserved(2)
selected_features(4) echoed_nonce(16)`. Status 0 accepts a non-empty feature
intersection; status 1 rejects it.

`auto` closes a failed probe carrier and opens one fresh legacy v0/v1 carrier;
no application stream exists before the ACK. The first successful result is
cached per client. `require` never downgrades. `off` remains the default and
emits byte-identical v0/v1 requests.

When padding is enabled, both sides wrap the first 16 writes. Each padded frame
is `payload_length(2) padding_length(2) payload padding`. Payloads larger than
65535 bytes are split. After 16 frames the byte stream is passed through raw.
The writer emits canonical frames; the reader accepts valid non-canonical frame
sizes subject to the same 65535-byte limits.

The padding bytes themselves carry no meaning and the reader discards
`padding_length` of them whatever they contain. The canonical writer selects a
padding length from 256 through 767 and fills the bytes from `crypto/rand`: the
header already announces the length, so a constant filler would contribute a
recognisable pattern rather than hide one. A peer that emits another valid
length or constant padding stays interoperable.

After the carrier request, protocol 0 starts the embedded SMUX v1 engine.
Protocol 2 starts HTTP/2 prior knowledge directly on the authenticated carrier,
without TLS, ALPN, or an HTTP/1 upgrade. Every logical H2MUX stream is one HTTP
CONNECT request to authority `localhost`. HTTP status 200 establishes the byte
stream; the request and response DATA bodies carry the common stream framing
below. The client may send the stream request before response headers arrive.

## H2MUX frame size

An H2MUX server advertises `SETTINGS_MAX_FRAME_SIZE` in its initial SETTINGS
frame. Go clients size the per-stream upload buffer of a body without
`Content-Length` — every H2MUX stream — from that value, so a large one costs
hundreds of kilobytes per concurrent stream on memory-constrained clients. The
setting is per inbound and leaves the `golang.org/x/net/http2` default of 1 MiB
in place when omitted:

```json
"smux": {
  "h2muxMaxReadFrameSize": 16384
}
```

An explicit value is one of 16384 through 16777215, the range RFC 9113 section
6.5.2 defines; anything else is rejected at configuration time. The setting
applies only to H2MUX carriers accepted through that inbound and never changes
SMUX carriers, which carry no HTTP/2 settings.

## Stream request and response

A new logical stream starts with `flags(2) destination`.

* Flag bit 0: UDP.
* Flag bit 1: every UDP datagram carries its own destination.

An address is `family(1) host port(2)`. Family 1 carries four IPv4 bytes,
family 3 carries `domain_length(1) domain`, and family 4 carries 16 IPv6 bytes.

The server response is one status byte. Status 0 is success. Status 1 is
followed by an unsigned-varint message length and UTF-8 diagnostic text. A
receiver must bound the diagnostic length before allocating memory.

Compatible servers may emit the response lazily with the first bytes written
by the destination. The client therefore consumes the status on its first read,
not before forwarding the request. Until that status arrives, it retains at
most 2 MiB of outbound stream bytes. A pre-response carrier failure closes the
failed session, removes that session from the selectable pool, opens one
replacement stream, and replays those bytes. Recovery may reuse a different
healthy pooled session and dials a new carrier only when the remaining pool
cannot serve the stream. A protocol status error is never retried, and payload
beyond the bounded replay
window disables replay rather than allocating without limit.

## Brutal bandwidth exchange

Brutal is opt-in and does not change carriers whose configuration leaves it
disabled. An enabled client opens one ordinary TCP stream to the domain
`_BrutalBwExchange` with port 0 and sends its receive ceiling as one unsigned
64-bit big-endian integer. It then reads the normal successful stream response
before consuming the Brutal response body.

The server replies with one boolean byte. A true value is followed by the
server's unsigned 64-bit big-endian receive ceiling. A false value is followed
by an unsigned-varint diagnostic length and that many UTF-8 bytes. Diagnostics
are bounded to 65535 bytes before allocation.

Each endpoint applies the smaller of its configured send ceiling and the
peer's advertised receive ceiling to the physical TCP carrier. Xray exposes
the client setting on outbound mux clients and the server setting per inbound:

```json
"smux": {
  "brutal-opts": {
    "enabled": true,
    "up": "1 Gbps",
    "down": "1 Gbps"
  }
}
```

The server reserves `_BrutalBwExchange:0` before routing, accepts it only as a
TCP stream, and permits one successful exchange per carrier for both SMUX and
H2MUX. It applies `min(server up, client down)` and advertises `server down`.
Disabled, malformed, duplicate, or out-of-range exchanges fail only their
control stream. If socket control may already have changed the physical TCP
socket, the server closes the carrier rather than leaving asymmetric
congestion control. The Linux carrier must have the `brutal`
congestion-control module available.

## UDP packets

This implementation always requests per-packet addressing. A datagram is
`destination payload_length(2) payload`. The payload is limited to 65535 bytes.
Malformed carrier framing closes the carrier. Malformed stream or packet
framing closes only that logical stream.

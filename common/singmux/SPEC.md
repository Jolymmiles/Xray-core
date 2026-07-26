# Xray SMUX wire protocol

This package implements the sing-mux compatible SMUX wire protocol without a
runtime dependency on sing-mux or another multiplexing library.

All multi-byte integers in the outer protocol are unsigned and big endian.
The embedded SMUX v1 carrier is specified in `ENGINE_SPEC.md`; its integers are
little endian as required for interoperability.

## Carrier request

The carrier is a TCP connection to `sp.mux.sing-box.arpa:444`.

* Version 0: `version(1) protocol(1)`. Protocol 0 is SMUX.
* Version 1: `version(1) protocol(1) padding(1) padding_length(2) padding(N)`.

When padding is enabled, both sides wrap the first 16 writes. Each padded frame
is `payload_length(2) padding_length(2) payload padding`. Payloads larger than
65535 bytes are split. After 16 frames the byte stream is passed through raw.
The writer emits canonical frames; the reader accepts valid non-canonical frame
sizes subject to the same 65535-byte limits.

The padding bytes themselves carry no meaning and the reader discards
`padding_length` of them whatever they contain. The writer fills them from
`crypto/rand`: the header already announces the length, so a constant filler
would contribute a recognisable pattern rather than hide one. A peer that emits
constant padding stays interoperable.

## Stream request and response

A new SMUX stream starts with `flags(2) destination`.

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
failed session, opens one replacement stream, and replays those bytes. A
protocol status error is never retried, and payload beyond the bounded replay
window disables replay rather than allocating without limit.

## UDP packets

This implementation always requests per-packet addressing. A datagram is
`destination payload_length(2) payload`. The payload is limited to 65535 bytes.
Malformed carrier framing closes the carrier. Malformed stream or packet
framing closes only that logical stream.

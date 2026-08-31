# MTProxy client transport specification

## Scope and provenance

This document specifies the client-facing MTProxy wire behavior implemented by
this package. The implementation is an independent Go design based on observed
wire behavior and interoperability requirements. GPL implementation source is
not copied into this repository.

## Obfuscated header

A client begins with 64 bytes. Bytes 8 through 55 are random-looking public key
material. Bytes 56 through 63 are the corresponding AES-CTR ciphertext for a
plaintext tail containing:

- bytes 56..59: little-endian transport tag;
- bytes 60..61: little-endian signed data-center identifier;
- bytes 62..63: random padding.

For a configured 16-byte secret, client-to-proxy material is:

    key = SHA256(header[8:40] || secret)
    iv  = header[40:56]

Proxy-to-client material uses the reversal of header[8:56]:

    key = SHA256(reverse(header[24:56]) || secret)
    iv  = reverse(header[8:24])

The client-to-proxy CTR stream consumes the full 64-byte header. The
proxy-to-client stream starts at offset zero. A secret authenticates only when
the decrypted tag is one of the supported tags. A wrong secret fails closed.

## Framing

All integer fields are little-endian.

### Abridged

The length is measured in 32-bit words. Values 1..126 use one byte. Larger
values use four bytes: 0x7f followed by a 24-bit word count. Bit 7 of the first
byte requests a quick acknowledgement. Payload length is always divisible by
four.

### Intermediate

A 32-bit byte length precedes the payload. Bit 31 requests a quick
acknowledgement. The remaining length must be at least four and divisible by
four.

### Padded intermediate

The prefix is the intermediate prefix, but its byte length includes zero to
three trailing transport-padding bytes. The MTProto payload is the length
rounded down to a multiple of four. A frame whose rounded payload is empty is
invalid.

## Ownership and limits

Length prefixes are validated before allocating body storage. Production code
must store large messages in Xray pooled MultiBuffers and apply AES-CTR in place
without coalescing the payload. The supported payload limit is a server policy,
not a value trusted from the peer.

A connection owns exactly one decrypt stream and one encrypt stream; calls in a
direction are serialized. Fragmented length prefixes and coalesced frames have
identical semantics. Malformed tags, overlong encodings, empty payloads,
misalignment, and configured-size violations terminate the connection.

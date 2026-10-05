# QUIC sniffer test corpus

The `quic-*.bin` files are client datagrams captured by the Hysteria project.
They are copied unchanged from
[`apernet/hysteria` tag `app/v2.13.0`](https://github.com/apernet/hysteria/tree/app/v2.13.0/extras/sniff/testdata),
where commit `4849cda3` ("feat(sniff): rework sniffing to handle multi-packet
QUIC ClientHellos", #1693) added them. Their git blob hashes match that tag.
Hysteria is distributed under the MIT License; its copyright and permission
notice is kept in [`LICENSE-MIT`](LICENSE-MIT).

Each file is one UDP datagram. Files that share a prefix belong to one QUIC
connection and are numbered in the order the client sent them.

| Prefix | Client | Server name | Notes |
| --- | --- | --- | --- |
| `quic-chrome153` | Chrome 153 | `chrome.sniff.test` | The ClientHello is shuffled across datagrams 0 and 1; datagram 2 retransmits the fragments of datagram 0, split differently. |
| `quic-firefox153esr` | Firefox 153 ESR | `firefox.sniff.test` | Each datagram pads with zero bytes after its Initial packet. |
| `quic-curl8.14-openssl3.5` | curl 8.14 with OpenSSL 3.5 | `curl.sniff.test` | The ClientHello spans both datagrams. |
| `quic-quiche` | quiche | `quiche.sniff.test` | Datagram 1 retransmits datagram 0; datagram 2 completes the ClientHello and pads with zero bytes. |
| `quic-ngtcp2-1.11` | ngtcp2 1.11 | `ngtcp2.sniff.test` | One datagram. |
| `quic-aioquic1.2` | aioquic 1.2 | `aioquic.sniff.test` | One datagram padded with zero bytes. |

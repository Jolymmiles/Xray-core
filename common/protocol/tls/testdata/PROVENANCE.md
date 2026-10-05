# TLS sniffer test corpus

The `tls-*.bin` files are the first TLS records of real clients, captured by
the Hysteria project. They are copied unchanged from
[`apernet/hysteria` tag `app/v2.13.0`](https://github.com/apernet/hysteria/tree/app/v2.13.0/extras/sniff/testdata),
where commit `4849cda3` ("feat(sniff): rework sniffing to handle multi-packet
QUIC ClientHellos", #1693) added them. Their git blob hashes match that tag.
Hysteria is distributed under the MIT License; its copyright and permission
notice is kept in [`LICENSE-MIT`](LICENSE-MIT).

Each file holds one handshake record carrying a whole ClientHello.

| File | Client | Server name |
| --- | --- | --- |
| `tls-chrome153.bin` | Chrome 153 | `chrome.sniff.test` |
| `tls-firefox153esr.bin` | Firefox 153 ESR | `firefox.sniff.test` |
| `tls-curl8.18-openssl3.5.bin` | curl 8.18 with OpenSSL 3.5 | `curl.sniff.test` |

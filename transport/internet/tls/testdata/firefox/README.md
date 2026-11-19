# Firefox 156 ClientHello fixtures

Each `.hex` file is the complete first TLS record of one connection of
Firefox 156.0.1 (official Linux x86_64 build), as the browser sent it.

| Fixture | Server name | Offers | Record | GREASE ECH | SHA-256 of the record |
| --- | ---: | --- | ---: | ---: | --- |
| `fresh-name107.hex` | 107 bytes | nothing | 1 985 | 282 | `d3105a4b1669b810b0162f14d48c861e2a3547498bdb21fb592f9c8ff24618bf` |
| `fresh-name108.hex` | 108 bytes | nothing | 2 018 | 314 | `8607200c588e815858d7d95b09d7b82dcfe06be79ea3895b3054e65f13704bf1` |
| `tls13-ticket-name6.hex` | `x.test` | a TLS 1.3 ticket, 224-byte identity | 2 439 | 570 | `4c5609a7286df93dcfd7d18065f8a9e669db4da4ffda3a9d2fc7690a86e55aee` |
| `tls13-ticket-name108.hex` | 108 bytes | a TLS 1.3 ticket, 336-byte identity | 2 749 | 666 | `c6d2ff76f0e250ecedcddf145479ea4560e5c65e92fa400b70134af4ec401efa` |
| `tls12-ticket-name6.hex` | `x.test` | a TLS 1.2 ticket of 192 bytes | 2 076 | 282 | `13dd3b98aaccb584f83546aceced5fc26d2f34eb8b864d000d47aaeda41188a1` |

"GREASE ECH" is the length of the body of extension 65037.

They were captured on November 18, 2026, on Debian 13. Firefox ran headless
with a fresh profile in its own user and network namespace and loaded pages
from servers on loopback: nginx with `ssl_early_data off` for the first four
fixtures, and `openssl s_server` capped at TLS 1.2 for the last. The page was
loaded again after the server closed the connection, which is where the
tickets come from. A relay in front of the server kept the client's first
record; the bytes are unchanged. Neither keys nor server traffic are kept.

`firefox_test.go` builds the `firefox` ClientHello for the same server name
and a ticket of the same size and compares the extensions in order, the
length of each, the record length, and every extension body except the key
shares, the tickets and the GREASE ECH.

The rule in `firefox.go` was fitted to 340 ClientHellos of Firefox 156.0.1
and 160.0, of which these are five: server names from 6 to 200 bytes, and
TLS 1.3 tickets with identities of seven lengths from 32 to 336 bytes, from
nginx, OpenSSL and Go's `crypto/tls`. It fits the 323 that carry no
`early_data`; with two more bytes counted for that extension it fits all
340. In the 262 first hellos the top bit of the encapsulated key's last
byte was set 128 times, and the AEAD was AES-128-GCM 113 times and
ChaCha20-Poly1305 149 times.

Not modelled: a ticket that allows early data. Firefox then also sends
`early_data` (extension 42) after `key_share`, and its GREASE ECH counts two
more bytes, which moves it to the next 32 at some name and ticket sizes.
Xray sends no early data and no such extension, which is what Firefox sends
with `security.tls.enable_0rtt_data` off.

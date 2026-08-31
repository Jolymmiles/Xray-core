# Xray MTProxy inbound

This inbound implements Telegram MTProxy client transports and forwards MTProto
packets through Telegram Middle-End servers. Fake TLS is protocol-local and
must not be combined with Xray TLS or REALITY stream security.

## Automatic Telegram upstream

    {
      "inbounds": [
        {
          "tag": "mtproxy-in",
          "listen": "0.0.0.0",
          "port": 443,
          "protocol": "mtproxy",
          "settings": {
            "clients": [
              {
                "email": "telegram-primary",
                "secret": "00112233445566778899aabbccddeeff"
              }
            ],
            "upstream": {
              "source": "telegram",
              "cacheDir": "/var/lib/xray/mtproxy",
              "refreshInterval": 86400,
              "proxyTag": "ffeeddccbbaa99887766554433221100"
            },
            "fakeTLS": {
              "only": true,
              "domains": ["cover.example.com"]
            }
          }
        }
      ]
    }

Automatic mode downloads only the fixed official endpoints
getProxySecret/getProxyConfig at core.telegram.org. A validated owner-only
last-known-good cache is used at startup. Valid refreshes are applied to new
connections without interrupting clients on the previous generation.

## Administrator-managed upstream files

    "upstream": {
      "source": "files",
      "secretFile": "/etc/xray/mtproxy/proxy-secret",
      "configFile": "/etc/xray/mtproxy/proxy-multi.conf",
      "proxyTag": "ffeeddccbbaa99887766554433221100"
    }

The upstream secret is raw bytes, not hexadecimal text. Do not add a trailing
newline. The proxy tag is optional attribution metadata from @MTProxybot and is
not an authentication secret.

## Client links

Padded intermediate uses the client-side dd marker followed by the raw secret:

    tg://proxy?server=proxy.example.com&port=443&secret=dd00112233445566778899aabbccddeeff

Fake TLS uses ee plus the same secret and the hexadecimal domain bytes. The
server configuration still receives only the 32 hexadecimal secret digits in
clients[].

## Dynamic secrets and revocation

The handler implements Xray's existing UserManager. HandlerService AddUser,
GetUser/GetUsers and RemoveUser operate on xray.proxy.mtproxy.Account. Email is
the stable management key. RemoveUser is an immediate hard revoke: new
handshakes fail, active client sockets close, and the logical Middle-End stream
is detached before the operation returns. There is no graceful-retirement mode
and no client secrets file.

The protocol has no secret selector, so authentication cost is linear. The hard
limit is 16 secrets per inbound. See BASELINE.md for measurements through
500,000 candidates.

## Resource and deployment notes

- Default maximum client packet: 1 MiB; absolute maximum: 4 MiB.
- Handshakes, frame bodies, Middle-End dials, response queues and writes are
  bounded and have deadlines. maxPacketSize × handshakeConcurrency may not
  exceed the 256 MiB aggregate frame-allocation budget.
- Fake TLS fallback is restricted to configured SNI domains. Replay protection
  uses a fixed-memory rotating Bloom filter; replayCacheCapacity is the expected
  number of authenticated handshakes per ten-minute window and has an
  approximately 0.15% combined false-positive rate near capacity.
- Middle-End key derivation binds socket addresses and ports. Deploy directly on
  the advertised public address; arbitrary NAT port/address rewriting is not
  currently supported.
- Automatic upstream refresh is control-plane work and never runs in a packet
  processing path.

# MTProxy testing

## Focused development

    GOTOOLCHAIN=auto go test ./proxy/mtproxy -count=1
    GOTOOLCHAIN=auto go test -race ./proxy/mtproxy -count=1
    GOTOOLCHAIN=auto go vet ./proxy/mtproxy ./infra/conf

## Configuration integration

    GOTOOLCHAIN=auto go test ./infra/conf ./app/proxyman/command \
      -run 'MTProxy|MtProxy|mtproxy' -count=1

The complete infra/conf suite also requires the repository geodata assets under
resources/. A missing geoip.dat/geosite.dat failure is environmental and must be
reported rather than retried or hidden.

## In-process integration

The current `TestMTProxyProcess*` tests run Handler directly inside the Go test
process, using net.Pipe for the inbound and independent loopback Middle-End
fixtures. Despite their historical names, they do not launch the Xray executable
or exercise the HandlerService RPC boundary. They cover padded framing, Fake
TLS, multiplexing, quick acknowledgements, direct RemoveUser calls, reconnect
and upstream replacement.

Run these in-process integration tests three times:

    GOTOOLCHAIN=auto go test -tags integration ./proxy/mtproxy \
      -run '^TestMTProxyProcess' -count=3 -v

## Executable and HandlerService E2E

The subprocess suite builds this checkout's `./main`, launches Xray with a real
JSON configuration, and connects TCP clients and a loopback Middle-End fixture.
It verifies:

- DD and fragmented EE handshakes and complete MTProto payload round trips;
- two independently authenticated clients sharing a physical Middle-End session;
- HandlerService user counts and RemoveUser over actual gRPC, including socket
  closure, logical Middle-End close, rejection of the removed secret, and an
  unrelated client's continued operation;
- byte-identical fragmented ClientHello plus coalesced payload fallback through
  the real dispatcher and a loopback cover endpoint;
- closure of both fallback directions after client EOF, cover EOF, RemoveInbound
  over gRPC, and graceful process shutdown;
- wrong DD secret, unlisted SNI, and malformed ClientHello rejection.

Run the nine leaf scenarios three times (21 Xray subprocesses, 27 leaf results):

    GOTOOLCHAIN=auto go test -tags integration ./proxy/mtproxy \
      -run '^TestMTProxySubprocess$' -count=3 -v

An explicit `XRAY_MTPROXY_E2E_BIN` may supply a previously built binary from the
same checkout, including a race-instrumented build. The general `XRAY_E2E_BIN`
is deliberately ignored because a main-branch binary may not contain MTProxy.
The startup log event is followed by a real HandlerService RPC; DD/EE readiness
is proven by the full TCP-to-Xray-to-Middle-End round trip. Failed operations
are not retried.

## Manual interoperability gate

Before merge, connect current official Telegram Desktop and Android clients in
DD and EE modes. Verify authorization, messages, large media transfer,
reconnect, secret deletion, and proxyTag attribution. Do not classify a local
codec fixture as official-client interoperability.

## Linux build

    artifact=/tmp/xray-mtproxy-linux-amd64
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOTOOLCHAIN=auto \
      go build -trimpath -ldflags='-s -w -buildid=' -o "$artifact" ./main
    file "$artifact"
    sha256sum "$artifact"
    go version -m "$artifact"

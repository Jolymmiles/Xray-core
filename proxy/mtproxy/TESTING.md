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

## Outstanding merge gates

A real Xray subprocess test must still exercise configuration loading,
HandlerService RemoveUser, and byte-identical allowlisted fallback, including
shutdown and cancellation. In-process fixtures do not satisfy this gate.

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

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

## Process interoperability

The integration suite must start a real Xray MTProxy inbound and an independent
local Middle-End fixture, then exercise:

- ordinary padded-intermediate (DD) framing;
- Fake TLS (EE), fragmented TLS records, and allowlisted fallback;
- multiple logical clients over one Middle-End connection;
- quick acknowledgements and close propagation;
- immediate hard revocation through HandlerService RemoveUser;
- Middle-End disconnect/reconnect and automatic upstream refresh.

Run process tests three times:

    GOTOOLCHAIN=auto go test -tags integration ./proxy/mtproxy \
      -run '^TestMTProxyProcess' -count=3 -v

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

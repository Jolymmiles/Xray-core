# SMUX Brutal Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in per-inbound Brutal server that negotiates the existing SMUX/H2MUX control stream, applies the bounded send rate to the physical TCP carrier, and never dispatches the reserved control destination to routing.

**Architecture:** The inbound JSON loader validates `smux.brutal-opts` into `proxyman.ReceiverConfig`. The TCP worker attaches immutable options to the accepted connection context, and `singmux.Service` creates one controller per carrier that intercepts `_BrutalBwExchange:0` before routing. The controller owns one negotiation attempt, applies `min(server up, client down)` through the existing socket-control function, and closes the carrier after partial activation failures.

**Tech Stack:** Go 1.26, protobuf, Xray connection contexts, in-tree SMUX/H2MUX, standard library synchronization and networking.

## Global Constraints

- Brutal is disabled by default and enabled independently per inbound.
- Preserve the existing wire bytes in `common/singmux/SPEC.md`.
- Do not add a dependency or import/copy GPL mux production source.
- Do not add YAMUX or unrelated H2MUX behavior.
- Keep generated protobuf generated; do not hand-edit `config.pb.go`.
- Use RED-GREEN-REFACTOR and record the initial expected failure for each behavior group.
- Do not commit until the maintainer explicitly asks for a commit.
- Linux/amd64 is the release target; Darwin tests prove development behavior only.

---

### Task 1: Per-inbound configuration and worker mapping

**Files:**
- Modify: `app/proxyman/config.proto`
- Regenerate: `app/proxyman/config.pb.go`
- Modify: `infra/conf/xray.go`
- Test: `infra/conf/xray_test.go`
- Modify: `app/proxyman/inbound/always.go`
- Modify: `app/proxyman/inbound/worker.go`
- Test: `app/proxyman/inbound/worker_performance_test.go`

**Interfaces:**
- Produces: `type InboundSMuxConfig struct { BrutalOpts *SMuxBrutalOpts }`
- Produces: `func (b *SMuxBrutalOpts) Build() (*proxyman.BrutalConfig, error)`
- Produces: `ReceiverConfig.SmuxSettings *proxyman.SmuxConfig`
- Produces: `func receiverBrutalOptions(*proxyman.ReceiverConfig) singmux.BrutalOptions`
- Consumes later: `singmux.ContextWithServerBrutalOptions(context.Context, singmux.BrutalOptions)` from Task 2.

- [x] **Step 1: Write failing configuration tests**

Add a table-driven `TestInboundSMuxConfigBuild` that unmarshals only the inbound shape and asserts literal values:

```go
func TestInboundSMuxConfigBuild(t *testing.T) {
	tests := []struct {
		name    string
		fields  string
		want    *proxyman.SmuxConfig
		wantErr bool
	}{
		{name: "disabled default", fields: `{}`, want: &proxyman.SmuxConfig{}},
		{
			name:   "independent limits",
			fields: `{"brutal-opts":{"enabled":true,"up":"800 Mbps","down":"1 Gbps"}}`,
			want: &proxyman.SmuxConfig{Brutal: &proxyman.BrutalConfig{
				Enabled: true, UpBps: 100_000_000, DownBps: 125_000_000,
			}},
		},
		{name: "below minimum", fields: `{"brutal-opts":{"enabled":true,"up":"64 KBps","down":"1 Gbps"}}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config InboundSMuxConfig
			common.Must(json.Unmarshal([]byte(test.fields), &config))
			got, err := config.Build()
			if test.wantErr {
				if err == nil { t.Fatal("expected an error") }
				return
			}
			common.Must(err)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("InboundSMuxConfig.Build() = %#v, want %#v", got, test.want)
			}
		})
	}
}
```

Add `TestReceiverBrutalOptions` in the inbound package. It asserts that nil settings produce the zero value and a receiver with `BrutalConfig{Enabled:true, UpBps:7, DownBps:9}` maps to `singmux.BrutalOptions{Enabled:true, SendBPS:7, ReceiveBPS:9}`.

- [x] **Step 2: Run the RED tests**

Run:

```sh
go test ./infra/conf ./app/proxyman/inbound -run 'Test(InboundSMuxConfigBuild|ReceiverBrutalOptions)$' -count=1
```

Expected: compile failure because `InboundSMuxConfig`, `ReceiverConfig.SmuxSettings`, and `receiverBrutalOptions` do not exist.

- [x] **Step 3: Add the protobuf and JSON configuration path**

Add field 7 to `ReceiverConfig`:

```proto
SmuxConfig smux_settings = 7;
```

Refactor the existing outbound builder so `SMuxBrutalOpts.Build` owns rate parsing and minimum validation:

```go
func (b *SMuxBrutalOpts) Build() (*proxyman.BrutalConfig, error) {
	if b == nil { return nil, nil }
	up, err := parseSMuxRate(b.Up)
	if err != nil { return nil, err }
	down, err := parseSMuxRate(b.Down)
	if err != nil { return nil, err }
	if b.Enabled && (up < smuxBrutalMinBPS || down < smuxBrutalMinBPS) {
		return nil, errors.New("SMUX Brutal rates must each be at least 65536 bytes per second")
	}
	return &proxyman.BrutalConfig{Enabled: b.Enabled, UpBps: up, DownBps: down}, nil
}
```

Add the inbound-only JSON type and field:

```go
type InboundSMuxConfig struct {
	BrutalOpts *SMuxBrutalOpts `json:"brutal-opts"`
}

func (c *InboundSMuxConfig) Build() (*proxyman.SmuxConfig, error) {
	brutal, err := c.BrutalOpts.Build()
	if err != nil { return nil, err }
	return &proxyman.SmuxConfig{Brutal: brutal}, nil
}
```

`InboundDetourConfig.Build` assigns the built value to `receiverSettings.SmuxSettings` before constructing the core inbound.

Regenerate only the affected protobuf using the repository root as the include path:

```sh
protoc --go_out=. --go_opt=paths=source_relative app/proxyman/config.proto
```

Confirm the generated header uses the repository's current `protoc-gen-go` version and inspect the generated diff instead of editing it.

- [x] **Step 4: Map receiver settings into each TCP worker**

Add the pure mapping helper in `always.go`:

```go
func receiverBrutalOptions(config *proxyman.ReceiverConfig) singmux.BrutalOptions {
	if config == nil || config.SmuxSettings == nil || config.SmuxSettings.Brutal == nil {
		return singmux.BrutalOptions{}
	}
	brutal := config.SmuxSettings.Brutal
	return singmux.BrutalOptions{Enabled: brutal.Enabled, SendBPS: brutal.UpBps, ReceiveBPS: brutal.DownBps}
}
```

Store that value in each `tcpWorker`. After `session.ContextWithConnection`, wrap the accepted connection context with `singmux.ContextWithServerBrutalOptions`. UDP workers do not receive Brutal options.

- [x] **Step 5: Run GREEN configuration tests and existing outbound parsing tests**

Run:

```sh
gofmt -w infra/conf/xray.go infra/conf/xray_test.go app/proxyman/inbound/always.go app/proxyman/inbound/worker.go app/proxyman/inbound/worker_performance_test.go
go test ./infra/conf ./app/proxyman/inbound -count=1
```

Expected: all tests pass; existing outbound `SMuxConfig` cases retain identical values.

---

### Task 2: Carrier-scoped Brutal controller and reserved destination

**Files:**
- Modify: `common/singmux/brutal.go`
- Test: `common/singmux/brutal_test.go`

**Interfaces:**
- Produces: `func ContextWithServerBrutalOptions(context.Context, BrutalOptions) context.Context`
- Produces: `func newServerBrutalController(context.Context, func(net.Conn, uint64) error) *serverBrutalController`
- Produces: `func (c *serverBrutalController) handle(context.Context, net.Conn, time.Time) (closeCarrier bool, err error)`
- Produces: `func isBrutalDestination(X.Destination) bool`
- Consumes: the existing `readBrutalRequest`, `writeBrutalResponse`, `SetBrutalOptions`, and `session.Inbound.Conn`.

- [x] **Step 1: Write failing controller behavior tests**

Add focused tests with `net.Pipe` and a literal fake socket-control function:

```go
func TestServerBrutalNegotiatesBoundedRate(t *testing.T) {
	physicalClient, physicalServer := net.Pipe()
	defer physicalClient.Close()
	defer physicalServer.Close()
	applied := make(chan uint64, 1)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physicalServer})
	ctx = ContextWithServerBrutalOptions(ctx, BrutalOptions{
		Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000,
	})
	controller := newServerBrutalController(ctx, func(conn net.Conn, rate uint64) error {
		if conn != physicalServer { t.Fatalf("physical connection mismatch") }
		applied <- rate
		return nil
	})
	client, server := net.Pipe()
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		_, err := controller.handle(ctx, server, time.Now().Add(time.Second))
		result <- err
	}()
	if err := writeBrutalRequest(client, 80_000_000); err != nil { t.Fatal(err) }
	gotReceive, err := readBrutalResponse(client)
	if err != nil { t.Fatal(err) }
	if gotReceive != 125_000_000 { t.Fatalf("server receive = %d", gotReceive) }
	if gotRate := <-applied; gotRate != 80_000_000 { t.Fatalf("applied = %d", gotRate) }
	if err := <-result; err != nil { t.Fatal(err) }
}
```

Add separate tests that catch these mutations:

- disabled options must return a negative response and never call socket control;
- client receive below 65536 B/s must return a negative response;
- a second valid exchange on the same controller must fail without reapplying;
- missing `session.Inbound.Conn` must fail;
- socket-control failure must request carrier closure;
- failure after socket activation while writing the response must request carrier closure;
- `_BrutalBwExchange` is reserved case-insensitively and never accepted with UDP or a nonzero port.

- [x] **Step 2: Run the RED controller tests**

Run:

```sh
go test ./common/singmux -run '^TestServerBrutal' -count=1 -v
```

Expected: compile failure because the server context and controller APIs do not exist.

- [x] **Step 3: Implement the minimal carrier controller**

Use a private typed context key and copy `BrutalOptions` by value. The controller stores immutable options, the physical connection, the injected setter, a mutex, and a `negotiated` boolean. Read and validate the request under the supplied deadline, then lock only the check-and-claim transition so a stalled malformed request does not hold the controller lock.

The successful rate is:

```go
sendBPS := min(c.options.SendBPS, clientReceiveBPS)
```

Return `closeCarrier=true` only after socket control may have changed the physical socket: setter failure or failure to deliver the success response. Error responses use the existing bounded `writeBrutalResponse`; tests assert success/failure behavior rather than exact diagnostic wording.

The reserved destination helper must match the domain without case sensitivity and let the service distinguish a valid TCP/port-0 control request from a malformed reserved request.

- [x] **Step 4: Run GREEN controller tests**

Run:

```sh
gofmt -w common/singmux/brutal.go common/singmux/brutal_test.go
go test ./common/singmux -run '^TestServerBrutal' -count=1 -v
```

Expected: all server controller tests pass.

---

### Task 3: Intercept the control stream in SMUX and H2MUX service paths

**Files:**
- Modify: `common/singmux/service.go`
- Modify: `common/singmux/h2mux_server.go`
- Create: `common/singmux/service_brutal_test.go`
- Modify: `common/singmux/service_h2mux_test.go`

**Interfaces:**
- Consumes: `newServerBrutalController` and `isBrutalDestination` from Task 2.
- Changes: `Service.handleStream` receives one controller shared by every stream on its carrier.
- Changes: `Service.serveH2Mux` and `Service.handleH2MuxStream` receive the same per-carrier controller.

- [x] **Step 1: Write a failing real SMUX service negotiation test**

Start the actual in-tree server and client session over a pipe. Supply a context with per-inbound options and `session.Inbound.Conn`, replace only `service.setBrutalOptions`, and use the existing client Brutal exchange. Assert:

```go
if got := <-applied; got != min(serverSendBPS, clientReceiveBPS) {
	t.Fatalf("server applied %d", got)
}
select {
case destination := <-dispatcher.target:
	t.Fatalf("Brutal control stream reached router: %s", destination)
default:
}
```

Then open an ordinary target stream on the same session and prove it still reaches the echo dispatcher. This catches implementations that close or consume the wrong stream.

- [x] **Step 2: Write failing rejection and per-inbound isolation tests**

Add real-session cases for disabled configuration, malformed reserved port, duplicate exchange, and socket-control failure. Start two carriers concurrently with different server limits and assert their captured applied rates remain independent.

- [x] **Step 3: Run SMUX service tests RED**

Run:

```sh
go test ./common/singmux -run '^TestServiceBrutal' -count=1 -v
```

Expected: failures show the special stream reaching the dispatcher or receiving no Brutal response.

- [x] **Step 4: Add service interception**

Initialize the service default setter in `NewService`:

```go
setBrutalOptions: SetBrutalOptions,
```

Create one controller immediately after the carrier request context is available. Pass it to both the MPL SMUX accept loop and `serveH2Mux`. In `handleStream`, after the normal stream handshake and before reader/writer adapters or `DispatchLink`, branch on the reserved domain:

```go
if isBrutalDestination(destination) {
	if flags&streamFlagUDP != 0 || destination.Port != 0 {
		_ = writeBrutalResponse(stream, 0, false, "invalid Brutal control destination")
		return
	}
	closeCarrier, _ := brutal.handle(ctx, stream, s.streamDeadline(ctx))
	if closeCarrier && brutal.physical != nil { _ = brutal.physical.Close() }
	return
}
```

The branch must release the pending-handshake slot before reading the Brutal body, exactly as ordinary streams release it after the fixed-size stream request. It must never create a packet adapter or call the dispatcher.

- [x] **Step 5: Run SMUX service tests GREEN**

Run:

```sh
gofmt -w common/singmux/service.go common/singmux/h2mux_server.go common/singmux/service_brutal_test.go common/singmux/service_h2mux_test.go
go test ./common/singmux -run '^TestServiceBrutal' -count=1 -v
```

Expected: negotiation, rejection, isolation, duplicate, failure, and ordinary-stream continuation tests pass.

- [x] **Step 6: Add and run H2MUX parity coverage**

Use the existing `startH2MuxService` helper with per-inbound context and a service-local setter. Open an HTTP/2 stream, write the normal stream request for `_BrutalBwExchange:0`, write the 8-byte receive ceiling, and assert the normal stream response followed by the successful Brutal response. Assert no dispatcher target is observed.

Run:

```sh
go test ./common/singmux -run '^TestServiceH2MuxBrutal' -count=1 -v
```

Expected: H2MUX uses the same controller and passes.

---

### Task 4: Documentation and focused verification

**Files:**
- Modify: `common/singmux/SPEC.md`
- Modify: `common/singmux/H2MUX_DESIGN.md`
- Modify: `common/singmux/TESTING.md`
- Modify: `common/singmux/PROVENANCE.md` only if the implementation boundary description changes.

**Interfaces:**
- Documents the exact JSON shape, per-inbound scope, one-negotiation rule, and failure behavior implemented in Tasks 1-3.

- [x] **Step 1: Update protocol and testing documentation**

Replace the statement that Xray exposes Brutal only on outbound clients. Document that server configuration is opt-in per inbound, the server applies `min(server up, client down)`, advertises `server down`, reserves the control destination before routing, and closes a partially activated carrier.

Add the focused commands from this plan to `TESTING.md`. Do not claim Linux kernel-module interoperability from a Darwin test.

- [x] **Step 2: Run changed-package verification**

Run sequentially:

```sh
go test ./common/singmux/... ./common/mux ./app/proxyman/inbound ./app/proxyman/outbound ./infra/conf -count=1
go test -race ./common/singmux/... ./common/mux -count=1
go test -gcflags=all=-d=checkptr=2 ./common/singmux ./app/proxyman/inbound -count=1
go vet ./common/singmux/... ./common/mux ./app/proxyman/inbound ./infra/conf
go run ./infra/vformat/main.go -mode check -pwd ./
```

Expected: every command exits 0.

- [x] **Step 3: Run process interoperability**

Run:

```sh
go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v
go test -tags integration ./common/singmux -run '^TestH2MUXProcessInteropMatrix$' -count=1 -v
```

Expected: all available Xray, sing-box, and Mihomo scenarios pass. Report a missing external binary or unsupported peer feature exactly; do not retry or weaken a case.

- [x] **Step 4: Build and inspect Linux/amd64**

Run:

```sh
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w -buildid=' \
  -o /tmp/Xray-linux-amd64-brutal-server ./main
file /tmp/Xray-linux-amd64-brutal-server
shasum -a 256 /tmp/Xray-linux-amd64-brutal-server
go version -m /tmp/Xray-linux-amd64-brutal-server
```

Expected: static stripped Linux amd64 executable with `CGO_ENABLED=0`, `GOAMD64=v1`, and the current module identity.

- [x] **Step 5: Inspect the final diff without committing**

Run:

```sh
git diff --check
git status --short --branch
git diff --stat
git diff -- app/proxyman/config.proto infra/conf/xray.go app/proxyman/inbound common/singmux
```

Expected: only the Brutal server implementation, its generated protobuf, tests, design/plan, and protocol documentation are present. Leave the branch uncommitted until the maintainer explicitly requests a commit.

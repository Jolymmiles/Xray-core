# SMUX Brutal Server Design

## Goal

Add an opt-in, per-inbound Brutal server implementation for the in-tree SMUX
and H2MUX stacks. A configured Xray inbound must negotiate bandwidth with a
compatible Brutal client, apply the negotiated send rate to the physical TCP
carrier, and keep the control stream out of the ordinary router.

## Scope

The implementation covers the existing sing-mux Brutal wire exchange described
in `common/singmux/SPEC.md`. It does not add YAMUX support, a global process
setting, automatic enablement, a new dependency, or a second wire protocol.
Production code remains independently implemented from the in-tree
specification and Xray interfaces; GPL mux source is not a production design
input and no external mux package is imported.

## Operator configuration

Each inbound may enable Brutal with independent send and receive ceilings:

```json
{
  "tag": "vless-brutal",
  "protocol": "vless",
  "smux": {
    "brutal-opts": {
      "enabled": true,
      "up": "1 Gbps",
      "down": "1 Gbps"
    }
  }
}
```

`up` is the maximum rate the server may send on the physical carrier. `down`
is the maximum rate the server is prepared to receive and advertises to the
client. The existing SMUX rate syntax and minimum of 65536 bytes per second
apply. Omitting `smux`, omitting `brutal-opts`, or setting `enabled` to false
keeps Brutal disabled. Client-only SMUX fields such as protocol and connection
pool limits are not accepted on an inbound.

The JSON loader builds an inbound-only configuration and stores its validated
Brutal values in `proxyman.ReceiverConfig`. The existing outbound
`SMuxBrutalOpts` parser is reused through one narrow build helper so inbound
and outbound rate semantics cannot drift.

## Per-inbound propagation

The TCP inbound worker copies the immutable Brutal options from
`ReceiverConfig` into the accepted connection's context. The context value is
defined by `common/singmux`; it contains only validated `BrutalOptions` and is
not mutable after connection admission.

The existing session metadata continues to own the physical accepted
connection in `session.Inbound.Conn`. No global Brutal state is added and
`session.Inbound` is not extended with feature-specific fields.

When an inbound dispatches `sp.mux.sing-box.arpa:444`, `common/mux.Server`
passes the same connection context to `singmux.Service.NewConnection`. The
service therefore sees both the options for that inbound and the exact
physical carrier that owns the SMUX or H2MUX session. Two inbounds can use
different limits without sharing configuration or negotiation state.

## Server control-stream path

`singmux.Service.NewConnection` creates one Brutal controller per physical
carrier. The controller owns:

- the copied per-inbound options;
- the physical connection from `session.Inbound.Conn`;
- one terminal negotiation state;
- the socket-control function used to apply the negotiated rate.

Every logical stream still performs the normal stream handshake. Before a
stream reaches `routing.Dispatcher`, the service reserves the domain
`_BrutalBwExchange`. The exact valid control destination is TCP port 0. A
reserved-domain request with another network or port is rejected and is never
sent to DNS or the router.

For a valid control stream, the server:

1. sends the normal successful stream response;
2. reads the client's unsigned 64-bit big-endian receive ceiling;
3. rejects disabled configuration, a rate below 65536 B/s, a missing physical
   TCP carrier, or a second negotiation on the same carrier;
4. computes `min(server up, client down)`;
5. applies `TCP_CONGESTION=brutal` and `TCP_BRUTAL_PARAMS` to the physical
   carrier;
6. sends a successful Brutal response containing the server's `down` ceiling;
7. closes only the completed control stream.

The same controller and handler are passed to the SMUX and H2MUX server paths,
so their negotiation behavior is identical.

## Failure and lifecycle rules

A protocol or configuration rejection sends the existing bounded UTF-8 Brutal
failure response and closes only the control stream. No rejected control
stream reaches the router and no socket option is changed.

The first valid negotiation attempt owns the carrier. Concurrent or later
attempts receive a failure response and cannot reconfigure the socket.

If socket control fails, the server sends a failure response when possible and
then closes the physical carrier. If socket control succeeds but the success
response cannot be delivered, the physical carrier is also closed. This avoids
leaving one endpoint using Brutal while the peer believes negotiation failed.
Malformed or truncated request bytes close the control stream without changing
the physical socket.

Context cancellation and carrier shutdown continue to use the existing SMUX
session ownership. The implementation adds no background retry, unbounded
queue, or goroutine per packet.

## Security properties

- Brutal is disabled by default and must be enabled on each inbound.
- An untrusted client cannot choose a send rate above the server's `up` limit.
- A client cannot reconfigure another inbound because options and controller
  state are scoped to its accepted carrier context.
- The reserved control destination cannot escape into routing or DNS.
- Partial activation closes the carrier instead of continuing asymmetrically.
- Rates are validated before socket control and diagnostics retain the existing
  allocation bound.

## Tests and acceptance

TDD begins with failing behavior tests for:

- inbound JSON parsing, disabled defaults, minimum rates, and independent
  per-inbound values;
- successful negotiation using the lower of server `up` and client `down`;
- advertising server `down` to the client;
- disabled, malformed, missing-carrier, duplicate, and socket-control failure
  responses;
- zero router dispatches for every reserved-domain control request;
- two concurrent carriers from different inbound contexts retaining different
  limits;
- the common behavior through both SMUX and H2MUX;
- a real in-tree SMUX client and server exchange with only the kernel syscall
  boundary replaced by a deterministic test function.

Verification runs the SMUX unit suite, `-race`, `-d=checkptr=2`, dependency-ban
tests, the applicable process interoperability gate, formatting and vet, and a
static Linux/amd64 build. A Linux runtime with the tcp-brutal kernel module is
still required before claiming real kernel-module interoperability or server
capacity.

## Expected files

- `infra/conf/xray.go` and `infra/conf/xray_test.go`: inbound JSON and shared
  Brutal option validation.
- `app/proxyman/config.proto` and generated `config.pb.go`: validated receiver
  configuration transport.
- `app/proxyman/inbound/worker.go` and focused tests: connection-context
  propagation.
- `common/singmux/brutal.go`: per-connection option context and controller
  behavior.
- `common/singmux/service.go`, `h2mux_server.go`, and service tests: reserved
  stream dispatch and lifecycle.
- `common/singmux/SPEC.md`, `H2MUX_DESIGN.md`, and testing documentation:
  server semantics and release evidence.

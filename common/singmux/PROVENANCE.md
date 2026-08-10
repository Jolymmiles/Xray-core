# SMUX provenance and license record

This document records the source and license boundaries of the in-tree SMUX
implementation. It is an engineering provenance record, not legal advice.

## In-tree implementation

The production stack is maintained entirely under `common/singmux`. It does
not import or vendor SagerNet, MetaCubeX, Hashicorp, xtaci, or another mux
implementation.

The embedded carrier in `internal/mplsmux` is a substantially rewritten SMUX
version 1 engine. Its public API and wire contract have recognizable lineage
from [`xtaci/smux` v1.5.24](https://github.com/xtaci/smux/tree/79ed6364e64973ccf475b1e14f7378f008c8a5af),
which is distributed under the
[MIT License](https://github.com/xtaci/smux/blob/79ed6364e64973ccf475b1e14f7378f008c8a5af/LICENSE).
The upstream copyright and permission notice is preserved in
[`internal/mplsmux/LICENSE-MIT`](internal/mplsmux/LICENSE-MIT). The in-tree
implementation and its modifications are distributed under the repository's
MPL-2.0 license.

The outer carrier, H2MUX adapter, padding, stream request, UDP framing, retry,
client-pool, Brutal bandwidth exchange, socket-control, and server-dispatch
layers were independently implemented from the in-tree wire specifications,
tests, the public HTTP/2 specification and API, black-box process captures, and
Xray interfaces. The implementation record and input boundary are in
[`CLEANROOM.md`](CLEANROOM.md). Process-level tests use sing-box and Mihomo
only as separately executed interoperability peers.

## Excluded source

[`SagerNet/sing-mux` v0.3.5](https://github.com/SagerNet/sing-mux/tree/6fb501d02534177fed5567ee8f63afbc825e2861)
is distributed under
[`GPL-3.0-or-later`](https://github.com/SagerNet/sing-mux/blob/6fb501d02534177fed5567ee8f63afbc825e2861/LICENSE).
Its production source is not copied, vendored, linked, or imported by this
stack. GPL implementations may be run as external compatibility peers but are
not design inputs for production code.

Older SagerNet SMUX revisions were also GPL-3.0-or-later, while current
[`SagerNet/smux`](https://github.com/SagerNet/smux/tree/f373f1e706bf7400e9ce3d2e3b80363b75937872)
and examined [`MetaCubeX/smux`](https://github.com/MetaCubeX/smux/tree/d0c8756d3141ce2c9aa1046df6a93985441c6033)
revisions preserve the xtaci MIT license. None of these implementations is a
production dependency.

## Release gate

The dependency-ban test recursively rejects direct production imports of
external mux libraries. The only external production import permitted in this
package is the repository's existing BSD-licensed `golang.org/x/net/http2`
module used to implement H2MUX. Release verification additionally requires
unit, race, checkptr, process interoperability, and Linux stress tests
documented in [`TESTING.md`](TESTING.md).

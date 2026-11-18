# xtls/reality — Xray-core fork copy

Source: `github.com/xtls/reality v0.0.0-20261108101329-4bb46b2afd8b`
(`h1:fAn11r21QiUY2oAGwENWb5ummjhWwMcs2WzkbjDMh+k=`), copied verbatim from the
Go module cache. The root `go.mod` replaces the module with this directory.
`LICENSE` (MPL-2.0) and `LICENSE-Go` (BSD) are unchanged.

## Fork changes

Keep this list complete; everything else must match upstream byte for byte.

- `fork_keyshare.go` and its call in `Server` (`tls.go`): a Client Hello that
  offers X25519MLKEM768 in neither `supported_groups` nor `key_share` may
  authenticate with its single X25519 key share. Upstream rejects every hello
  without an X25519MLKEM768 key share, which locks out clients such as
  sing-box that strip the hybrid group. Hellos that offer the hybrid group
  keep upstream's rules. Covered by
  `transport/internet/reality/keyshare_test.go`.
- `Config.RequireMLKEM` (`common.go`, copied in `Clone`), read by
  `fork_keyshare.go`: when set, the change above is off and every hello
  without an X25519MLKEM768 key share is rejected, as upstream does. Xray's
  `realitySettings.requireMlkem` sets it; it is off by default. Covered by the
  same test.

- `Server` (`tls.go`), the fallback copy from the target to the client: when
  the copy ends with an error, such as a reset from the target, the client
  connection is closed instead of half-closed. A client that stayed silent
  otherwise held `Server` and its goroutines until its own socket timed out.
  This is upstream's `8530a57` ("Try pass RST"), which upstream's main does
  not carry; drop this entry once an update brings it. Covered by
  `transport/internet/reality/fallback_close_test.go`.

## Updating

1. `go mod download -json github.com/xtls/reality@<version>` and copy the
   module directory over this one.
2. Reapply the changes listed above.
3. Check that `diff -r <module cache dir> third_party/reality` shows only
   those changes plus this file, then run the REALITY gates in `AGENTS.md`.

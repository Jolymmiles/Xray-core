# xtls/reality — Xray-core fork copy

Source: `github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0`
(`h1:rb+fKQFhz+5I2PPuQsNYxI5mUU840XWYtRF0ZBjvkws=`), copied verbatim from the
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

## Updating

1. `go mod download -json github.com/xtls/reality@<version>` and copy the
   module directory over this one.
2. Reapply the changes listed above.
3. Check that `diff -r <module cache dir> third_party/reality` shows only
   those changes plus this file, then run the REALITY gates in `AGENTS.md`.

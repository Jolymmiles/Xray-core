#!/bin/sh
# setup.sh <xray-git-dir> <new-ref> <old-ref>: prepare the stand in
# $STAND_WORK (default ~/.cache/realitystand), without root.
#
# - nginx, HAProxy, tshark, certutil and pasta from Debian packages,
#   unpacked under $STAND_WORK/root (install.sh);
# - Google Chrome stable and Caddy (checked against its release checksums);
# - a copy of tcpdump: the system one runs under an AppArmor profile that
#   refuses signals and writes to hidden directories;
# - certificate chains shaped like Let's Encrypt's (certs.sh);
# - xray-new and xray-old built from the two refs.
# Firefox comes from the system. The full `browsers` group also needs Edge
# and Firefox 156.0.1 and 160.0 under $STAND_WORK/root/opt; README.md says
# where each goes. setup.sh does not download them.
set -eu
xray=$1 new=$2 old=$3
here=$(cd "$(dirname "$0")" && pwd)
work=${STAND_WORK:-$HOME/.cache/realitystand}
mkdir -p "$work/bin" "$work/dl" "$work/certs" "$work/runs"
STAND_WORK=$work "$here/install.sh" nginx haproxy tshark libnss3-tools passt

cd "$work/dl"
curl -fsSL -o chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
dpkg-deb -x chrome.deb "$work/root"
caddy=2.11.9
curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v$caddy/caddy_${caddy}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v$caddy/caddy_${caddy}_checksums.txt"
grep "caddy_${caddy}_linux_amd64.tar.gz" "caddy_${caddy}_checksums.txt" | sha512sum -c -
tar -xzf "caddy_${caddy}_linux_amd64.tar.gz" -C "$work/bin" caddy
cp /usr/bin/tcpdump "$work/bin/tcpdump"

"$here/certs.sh" "$work/certs/real"
mkdir -p "$work/www"
echo '<html><body>stand</body></html>' > "$work/www/index.html"
head -c 5000000 /dev/urandom > "$work/www/blob5m"
head -c 1000000 /dev/urandom > "$work/www/blob1m"

for side in new old; do
  eval ref=\$$side
  tree=$(mktemp -d)
  git -C "$xray" worktree add -q --detach "$tree" "$ref"
  (cd "$tree" && GOFLAGS=-tags=http2legacy go build -trimpath -o "$work/bin/xray-$side" ./main)
  git -C "$xray" worktree remove --force "$tree"
done
echo "stand ready in $work"

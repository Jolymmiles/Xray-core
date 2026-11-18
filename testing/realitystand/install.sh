#!/bin/sh
# install.sh <package>...: download Debian packages with the dependencies the
# system lacks and unpack them under $PREFIX, without root and without
# touching the system. Run the programs with env.sh.
set -eu
work=${STAND_WORK:-$HOME/.cache/realitystand}
PREFIX=${PREFIX:-$work/root}
debs=$work/debs
mkdir -p "$PREFIX" "$debs"
cd "$debs"
want=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
  --no-breaks --no-replaces --no-enhances "$@" 2>/dev/null | grep '^[a-z0-9]' | sort -u)
missing=
for p in $want; do
  # virtual packages have no candidate; installed ones are already there
  apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [0-9]' || continue
  dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && continue
  missing="$missing $p"
done
echo "downloading:$missing"
[ -z "$missing" ] || apt-get download $missing
for d in *.deb; do
  [ -f "$d" ] || continue
  dpkg-deb -x "$d" "$PREFIX"
done
echo "unpacked into $PREFIX"

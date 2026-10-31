#!/usr/bin/env bash
# Download the pinned longterm kernel tarball, verify sha256 against kernel.org's list, extract.
# --check: compare VERSION to the current longterm release for the series and exit 1 if behind.
source "$(dirname "$0")/_env.sh"

if [[ "${1:-}" == "--check" ]]; then
  cur="$(curl -sS https://www.kernel.org/releases.json | python3 -c '
import json,sys
series=sys.argv[1]
for r in json.load(sys.stdin)["releases"]:
    if r["version"].startswith(series+"."):
        print(r["version"]); break
' "$KERNEL_SERIES")"
  [[ -n "$cur" ]] || die "series $KERNEL_SERIES not found on kernel.org (EOL?)"
  if [[ "$cur" == "$KERNEL_VERSION" ]]; then
    echo "up to date: $KERNEL_VERSION"
  else
    echo "BEHIND: pinned $KERNEL_VERSION, current longterm $cur. Bump VERSION, then make fetch config build check."
    exit 1
  fi
  exit 0
fi

mkdir -p "$WORK"
tar="$WORK/linux-$KERNEL_VERSION.tar.xz"
sums="$WORK/sha256sums.asc"
[[ -f "$tar" ]] || { note "downloading linux-$KERNEL_VERSION"; curl -sSL -o "$tar" "$KERNEL_URL/linux-$KERNEL_VERSION.tar.xz"; }
curl -sSL -o "$sums" "$KERNEL_URL/sha256sums.asc"
expected="$(grep " linux-$KERNEL_VERSION.tar.xz\$" "$sums" | awk '{print $1}')"
[[ -n "$expected" ]] || die "linux-$KERNEL_VERSION.tar.xz not in kernel.org sha256sums"
echo "$expected  $tar" | sha256sum -c - || die "kernel tarball sha256 mismatch"
if [[ ! -d "$SRC" ]]; then
  note "extracting"
  tar xJf "$tar" -C "$WORK"
fi
echo "source: $SRC"

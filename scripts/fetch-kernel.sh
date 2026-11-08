#!/usr/bin/env bash
# Download the pinned longterm kernel tarball, verify it against KERNEL_SHA256 in VERSION and against
# kernel.org's list, extract, apply patches/*.patch (see patches/README.md).
# --check: compare VERSION to the current longterm release for the series and exit 1 if behind.
# --pin:   print the KERNEL_SHA256 line for the version in VERSION (for a bump).
source "$(dirname "$0")/_env.sh"

if [[ "${1:-}" == "--check" ]]; then
  cur="$(curl -fsS https://www.kernel.org/releases.json | python3 -c '
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
    echo "BEHIND: pinned $KERNEL_VERSION, current longterm $cur. Bump VERSION (scripts/fetch-kernel.sh --pin), then make fetch config build check."
    exit 1
  fi
  exit 0
fi

mkdir -p "$WORK"
tar="$WORK/linux-$KERNEL_VERSION.tar.xz"
sums="$WORK/sha256sums.asc"
# Downloads go to a .part file and are moved into place only when complete: a failed or partial
# download (or an HTML error page: -f) never sits at the final path.
fetch() { curl -fsSL --retry 2 -o "$2.part" "$1" && mv -f -- "$2.part" "$2"; }

# kernel.org's sha256 list. It's clearsigned by the kernel.org checksum autosigner; gpg checks that
# signature if the key is in your keyring (gpg --locate-keys autosigner@kernel.org fetches it over WKD).
kernel_org_sum() {
  fetch "$KERNEL_URL/sha256sums.asc" "$sums" || return 1
  grep " linux-$KERNEL_VERSION.tar.xz\$" "$sums" | awk '{print $1}'
}
sig_status() {
  command -v gpg >/dev/null || { echo "not checked (no gpg)"; return; }
  if gpg --batch --quiet --verify "$sums" 2>/dev/null; then echo "good signature"
  else echo "not verified (no key, or a bad signature: gpg --verify $sums)"; fi
}

if [[ "${1:-}" == "--pin" ]]; then
  sum="$(kernel_org_sum)" || die "can't download $KERNEL_URL/sha256sums.asc"
  [[ -n "$sum" ]] || die "linux-$KERNEL_VERSION.tar.xz not in kernel.org sha256sums"
  echo "kernel.org sha256sums.asc signature: $(sig_status)"
  echo "put this in VERSION:"
  echo "KERNEL_SHA256=$sum"
  exit 0
fi

# The pin in VERSION is what counts; kernel.org's list is a second, independent check.
[[ "${KERNEL_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || die "VERSION has no KERNEL_SHA256 for $KERNEL_VERSION; run scripts/fetch-kernel.sh --pin"
pinned_ok() { echo "$KERNEL_SHA256  $1" | sha256sum -c --quiet - >/dev/null 2>&1; }
if [[ -f "$tar" ]] && ! pinned_ok "$tar"; then
  note "cached $(basename "$tar") doesn't match KERNEL_SHA256; downloading it again"
  rm -f -- "$tar"
fi
if [[ ! -f "$tar" ]]; then
  note "downloading linux-$KERNEL_VERSION"
  fetch "$KERNEL_URL/linux-$KERNEL_VERSION.tar.xz" "$tar.dl" || die "download failed"
  pinned_ok "$tar.dl" || { rm -f -- "$tar.dl"; die "downloaded tarball does not match KERNEL_SHA256"; }
  mv -f -- "$tar.dl" "$tar"
fi
echo "$(basename "$tar"): matches KERNEL_SHA256"
sum="$(kernel_org_sum)" || sum=""
if [[ -z "$sum" ]]; then
  echo "warn: couldn't get kernel.org's sha256sums entry for it; relying on the pin"
elif [[ "$sum" != "$KERNEL_SHA256" ]]; then
  die "kernel.org's sha256sums disagrees with KERNEL_SHA256 for linux-$KERNEL_VERSION.tar.xz"
else
  echo "kernel.org sha256sums agrees (signature: $(sig_status))"
fi

# Extract into a temporary directory, move it into place, then mark it complete, so an interrupted
# extraction can never pass for a source tree. A tree from before the marker existed is compared
# against the tarball once instead of being replaced.
marker="$SRC/.lean-kernel-extracted"
pmarker="$SRC/.lean-kernel-patched"
extract() {
  note "extracting"
  local tmp="$WORK/.extract.$$"
  rm -r -f -- "$tmp"; mkdir -p "$tmp"
  tar xJf "$tar" -C "$tmp" || { rm -r -f -- "$tmp"; die "extraction failed"; }
  [[ -d "$tmp/linux-$KERNEL_VERSION" ]] || { rm -r -f -- "$tmp"; die "tarball has no linux-$KERNEL_VERSION/"; }
  rm -r -f -- "$SRC"
  mv -- "$tmp/linux-$KERNEL_VERSION" "$SRC"
  rmdir -- "$tmp"
  echo "$KERNEL_SHA256" > "$marker"
}
# patches/*.patch, in name order, with GNU patch or (RHEL 10 has no patch package by default) git apply,
# which works outside a repository. patch_check is a dry run: it fails on a patch that does not apply,
# including one the tree already carries, so a tree with any other patch set is re-extracted first.
# .lean-kernel-patched then records PATCHSET (the sha256 of the set, from _env.sh).
if command -v patch >/dev/null 2>&1; then
  patch_check() { patch -p1 -s -N -r - --dry-run -d "$SRC" < "$1" >/dev/null 2>&1; }
  patch_apply() { patch -p1 -s -N -r - --no-backup-if-mismatch -d "$SRC" < "$1"; }
elif command -v git >/dev/null 2>&1; then
  patch_check() { git -C "$SRC" apply --check "$1" >/dev/null 2>&1; }
  patch_apply() { git -C "$SRC" apply "$1"; }
else
  die "neither patch nor git is installed; one is needed to apply patches/ ($PKG_INSTALL patch)"
fi
patches_check() { local p; for p in "${PATCHES[@]}"; do patch_check "$p" || return 1; done; }
apply_patches() {
  local p
  for p in "${PATCHES[@]}"; do
    note "applying $(basename "$p")"
    patch_apply "$p" || die "$(basename "$p") does not apply to linux-$KERNEL_VERSION: merged upstream (drop it) or needs a rebase (see patches/README.md)"
  done
  echo "$PATCHSET" > "$pmarker"
}
tree_ok()    { [[ -f "$marker" && "$(cat "$marker")" == "$KERNEL_SHA256" ]]; }
patched_ok() { [[ -f "$pmarker" && "$(cat "$pmarker")" == "$PATCHSET" ]]; }
if tree_ok && patched_ok; then
  :
else
  if ! tree_ok; then
    if [[ -d "$SRC" && ! -f "$marker" ]] && tar --compare -Jf "$tar" -C "$WORK" >/dev/null 2>&1; then
      echo "$KERNEL_SHA256" > "$marker"
      note "existing source tree matches the tarball"
    else
      extract
    fi
  fi
  if [[ -f "$pmarker" ]] || ! patches_check; then
    note "source tree carries another patch set; re-extracting"
    extract
    patches_check || die "patches/ do not apply to a fresh linux-$KERNEL_VERSION tree (see patches/README.md)"
  fi
  apply_patches
fi
echo "source: $SRC (${#PATCHES[@]} patches applied)"

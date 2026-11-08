#!/usr/bin/env bash
# The Firecracker bump: check for a newer release, and pin one with every check the release offers.
#
#   scripts/fetch-firecracker.sh --check                   VERSION vs. the current GitHub release; exit 1 if behind
#   scripts/fetch-firecracker.sh --pin <version> [--via HOST] [--allow-fresh]
#       download release <version> (v1.17.0 or 1.17.0) into bin/ under the name make deps uses, verify it,
#       and print the VERSION lines to paste.
#
# What --pin establishes, and what it cannot. Firecracker signs nothing: its tags are annotated but unsigned
# (checked v1.14.0-v1.17.0), the release commits are unsigned, the tarball has no detached signature and no
# GitHub artifact attestation, and PGP-KEY.asc in its repo is for encrypting security disclosures. So there is
# no signature to verify. The pin in VERSION is the anchor: whatever we fetch and inspect today is what every
# later make deps and jail-setup must reproduce byte for byte. --pin therefore spends its effort on the one
# moment that anchor is set:
#   1. release metadata (GitHub API): not a draft or pre-release; its tag's commit, so the source the binary
#      claims to come from is on record; the asset's created_at vs updated_at (a tarball re-uploaded after the
#      release went out is a red flag); release age (--allow-fresh to pin one younger than 2 days: a bad
#      upload is usually noticed within that).
#   2. the tarball's sha256 against the release's published .sha256.txt (same origin, so this detects
#      corruption and a swapped tarball whose .txt was not swapped with it, not a complete substitution).
#   3. --via HOST: the same URL fetched and hashed from another machine over ssh, so a substitution would
#      have to reach both network paths. Recommended when a second machine is at hand (e.g. --via centos10).
#   4. the tarball's own SHA256SUMS over its contents, and firecracker --version reporting the version.
# Everything is downloaded to .dl names and moved into place only after all checks pass.
source "$(dirname "$0")/_env.sh"

api="https://api.github.com/repos/firecracker-microvm/firecracker"
dl="https://github.com/firecracker-microvm/firecracker/releases/download"
json() { python3 -I -c "import json,sys; r=json.load(sys.stdin); $1"; }
get() { curl -fsSL --retry 2 "$@"; }

if [[ "${1:-}" == "--check" ]]; then
  cur="$(get "$api/releases/latest" | json 'print(r["tag_name"])')" || die "can't read the latest release from GitHub"
  if [[ "$cur" == "$FIRECRACKER_VERSION" ]]; then
    echo "up to date: $FIRECRACKER_VERSION"
  else
    echo "BEHIND: pinned $FIRECRACKER_VERSION, current release $cur. Pin it: scripts/fetch-firecracker.sh --pin $cur [--via HOST], then make deps; the jail: sudo scripts/jail-setup.sh"
    exit 1
  fi
  exit 0
fi

[[ "${1:-}" == "--pin" ]] || die "usage: $0 --check | --pin <version> [--via HOST] [--allow-fresh]"
v="${2:?usage: $0 --pin <version> [--via HOST] [--allow-fresh]}"; v="v${v#v}"; shift 2
via=""; allow_fresh=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --via) via="${2:?--via needs a host}"; shift 2 ;;
    --allow-fresh) allow_fresh=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
name="firecracker-$v-x86_64.tgz"
url="$dl/$v/$name"
warn=0

# 1. Release metadata.
meta="$(get "$api/releases/tags/$v")" || die "no release $v on GitHub"
read -r draft pre published asset_created asset_updated sum_created sum_updated < <(json '
a={x["name"]:x for x in r["assets"]}
t=a.get("'"$name"'"); s=a.get("'"$name"'.sha256.txt")
if not t or not s: sys.exit("release lacks '"$name"' or its .sha256.txt")
print(r["draft"], r["prerelease"], r["published_at"], t["created_at"], t["updated_at"], s["created_at"], s["updated_at"])' <<<"$meta")
[[ "$draft" == False && "$pre" == False ]] || die "$v is a draft or pre-release (draft=$draft prerelease=$pre)"
ref="$(get "$api/git/ref/tags/$v")" || die "no tag $v"
read -r otype osha < <(json 'print(r["object"]["type"], r["object"]["sha"])' <<<"$ref")
commit="$osha"
[[ "$otype" == tag ]] && commit="$(get "$api/git/tags/$osha" | json 'print(r["object"]["sha"])')"
echo "release:     $v, published $published, tag -> commit $commit (tags are unsigned; this is what the release claims to be built from)"
to_epoch() { date -u -d "$1" +%s; }
if (( $(to_epoch "$asset_updated") - $(to_epoch "$asset_created") > 300 )); then
  echo "WARN: $name was re-uploaded: created $asset_created, updated $asset_updated. Find out why before pinning."; warn=1
fi
if (( $(to_epoch "$sum_updated") - $(to_epoch "$sum_created") > 300 )); then
  echo "WARN: $name.sha256.txt was re-uploaded: created $sum_created, updated $sum_updated."; warn=1
fi
age_days=$(( ( $(date -u +%s) - $(to_epoch "$published") ) / 86400 ))
if (( age_days < 2 )) && [[ $allow_fresh == 0 ]]; then
  die "release $v is $age_days day(s) old; a bad upload is usually caught within two. --allow-fresh to pin it anyway"
fi
echo "assets:      tarball uploaded $asset_created, checksum file $sum_created, release age $age_days days"

# 2. Download, and the published checksum.
mkdir -p "$BIN"
tgz="$BIN/$name"
get -o "$tgz.dl" "$url" || die "download failed: $url"
pub="$(get "$url.sha256.txt" | awk '{print $1}')" || die "can't download $url.sha256.txt"
[[ "$pub" =~ ^[0-9a-f]{64}$ ]] || die "published checksum file is malformed"
sum="$(sha256sum "$tgz.dl" | awk '{print $1}')"
[[ "$sum" == "$pub" ]] || { rm -f -- "$tgz.dl"; die "downloaded tarball sha256 $sum != published $pub"; }
echo "sha256:      $sum (matches the release's .sha256.txt)"

# 3. The same bytes seen from another machine.
if [[ -n "$via" ]]; then
  rsum="$(ssh -o BatchMode=yes "$via" "curl -fsSL --retry 2 '$url' | sha256sum | cut -c1-64")" || die "fetch via $via failed"
  rpub="$(ssh -o BatchMode=yes "$via" "curl -fsSL --retry 2 '$url.sha256.txt' | cut -c1-64")" || die "checksum fetch via $via failed"
  [[ "$rsum" == "$sum" && "$rpub" == "$pub" ]] || { rm -f -- "$tgz.dl"; die "via $via: tarball $rsum, published $rpub; here: $sum. The two network paths disagree: do not pin"; }
  echo "via $via:  same tarball and same published checksum"
else
  echo "via:         not used (--via HOST fetches from a second machine; recommended)"; warn=1
fi

# 4. Inside the tarball.
tmp="$(mktemp -d)"; trap 'rm -r -f -- "$tmp"' EXIT
tar xzf "$tgz.dl" -C "$tmp" || die "tarball does not extract"
rel="$tmp/release-$v-x86_64"
[[ -d "$rel" ]] || die "tarball has no release-$v-x86_64/"
( cd "$rel" && sha256sum --quiet -c SHA256SUMS ) || die "the tarball's own SHA256SUMS do not match its contents"
ver="$("$rel/firecracker-$v-x86_64" --version 2>/dev/null | head -1)" || die "firecracker binary does not run here"
[[ "$ver" == "Firecracker $v" ]] || die "binary reports '$ver', expected 'Firecracker $v'"
for f in jailer seccompiler-bin seccomp-filter; do ls "$rel/$f-$v-x86_64"* >/dev/null 2>&1 || die "tarball lacks $f"; done
echo "contents:    SHA256SUMS ok; firecracker, jailer, seccompiler-bin, seccomp-filter present; '$ver'"

mv -f -- "$tgz.dl" "$tgz"
echo
[[ $warn == 0 ]] || echo "(warnings above: read them before pasting)"
echo "put these in VERSION, then: make deps; sudo scripts/jail-setup.sh (the jail's copies and its seccomp filter); make test agent-test"
echo "FIRECRACKER_VERSION=$v"
echo "FIRECRACKER_SHA256=$sum"
echo "# $v: published $published, tag commit $commit, pinned $(date -u +%Y-%m-%d)${via:+ (hash confirmed via $via)}"

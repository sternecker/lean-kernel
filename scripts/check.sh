#!/usr/bin/env bash
# Grade out/.config against KSPP recommendations with kernel-hardening-checker, and fail on any FAIL
# that isn't reviewed in configs/checker-accepted.txt. The checker is pinned to KHC_COMMIT in VERSION
# and lives in work/ (no system packages); a checkout at any other commit, or with local changes, is
# refused before it runs.
source "$(dirname "$0")/_env.sh"

[[ -f "$OUT/.config" ]] || die "no out/.config; run make config"
[[ "${KHC_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || die "VERSION has no KHC_COMMIT"
khc="$WORK/kernel-hardening-checker"
if [[ ! -d "$khc/.git" ]]; then
  note "cloning kernel-hardening-checker"
  git clone -q "$KHC_URL" "$khc"
fi
if [[ "$(git -C "$khc" rev-parse HEAD)" != "$KHC_COMMIT" ]]; then
  git -C "$khc" cat-file -e "$KHC_COMMIT^{commit}" 2>/dev/null || git -C "$khc" fetch -q origin
  git -C "$khc" -c advice.detachedHead=false checkout -q --detach "$KHC_COMMIT"
fi
[[ "$(git -C "$khc" rev-parse HEAD)" == "$KHC_COMMIT" ]] || die "kernel-hardening-checker is not at KHC_COMMIT"
[[ -z "$(git -C "$khc" status --porcelain)" ]] || die "kernel-hardening-checker checkout has local changes; refusing to run it"

build=gcc; [[ "$LLVM" == "1" ]] && build=clang
report="$(cd "$khc" && python3 -I ./bin/kernel-hardening-checker -c "$OUT/.config" -m show_fail)" \
  || die "kernel-hardening-checker failed to run"
echo "$report"
echo

declare -A accepted=()
while read -r opt which _; do
  [[ -z "$opt" || "$opt" == \#* ]] && continue
  [[ "$which" == all || "$which" == "$build" ]] && accepted[$opt]=1
done < "$ROOT/configs/checker-accepted.txt"

declare -A failing=()
new=()
while read -r opt; do
  failing[$opt]=1
  [[ -v "accepted[$opt]" ]] || new+=("$opt")
done < <(awk -F'|' '$NF ~ /FAIL/ { gsub(/ /, "", $1); if ($1 ~ /^CONFIG_/) print $1 }' <<< "$report")
for opt in "${!accepted[@]}"; do
  [[ -v "failing[$opt]" ]] || echo "note: $opt is accepted for $build builds but passes now; remove it from configs/checker-accepted.txt"
done
echo "checker FAILs: ${#failing[@]}, accepted for $build builds: $(( ${#failing[@]} - ${#new[@]} )), not accepted: ${#new[@]}"
if [[ ${#new[@]} -gt 0 ]]; then
  printf 'not accepted: %s\n' "${new[@]}" >&2
  die "new hardening-checker FAILs. Fix the config, or review each and add it to configs/checker-accepted.txt with the reason"
fi
echo "check: ok"

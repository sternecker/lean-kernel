#!/usr/bin/env bash
# Grade out/.config against KSPP recommendations with kernel-hardening-checker.
# Installs the checker into work/ (no system packages). Shows failures only.
source "$(dirname "$0")/_env.sh"

[[ -f "$OUT/.config" ]] || die "no out/.config; run make config"
khc="$WORK/kernel-hardening-checker"
if [[ ! -d "$khc" ]]; then
  note "cloning kernel-hardening-checker"
  git clone -q --depth 1 https://github.com/a13xp0p0v/kernel-hardening-checker "$khc"
fi
cd "$khc"
python3 -I ./bin/kernel-hardening-checker -c "$OUT/.config" -m show_fail || true
echo
echo "Read each FAIL: some are intentional for a microVM guest (no modules, no ACPI). Record accepted ones in HOWTO.md under 'Accepted checker failures'."

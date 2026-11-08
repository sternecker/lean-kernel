#!/usr/bin/env bash
# Boot out/bzImage headless with a test rootfs whose init runs tests/probe.c, then pass or fail on
# the probe's result. The probe tries every cut and hardening claim as root and as uid 65534,
# then once more under guest/jail-exec (the in-guest seccomp launcher).
# Uses the same kernel command line as make run (vm/vm.json.in). Log: out/test.log.
source "$(dirname "$0")/_env.sh"

[[ -x "$FC" ]] || die "firecracker missing; run make deps"
[[ -f "$OUT/bzImage" ]] || die "no out/bzImage; run make build"

note "building probe and jail-exec (static)"
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/probe" "$ROOT/tests/probe.c"
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/jail-exec" "$ROOT/guest/jail-exec.c"
PROBE="$OUT/probe" JAIL_EXEC="$OUT/jail-exec" "$ROOT/scripts/mkrootfs.sh" >/dev/null

cfg="$OUT/vm-test.json"
sed -e "s|@KERNEL@|$OUT/bzImage|" -e "s|@ROOTFS@|$OUT/rootfs-test.ext4|" -e "s|@VSOCK@|$OUT/vsock-test.sock|" \
    "$ROOT/vm/vm.json.in" > "$cfg"
# Tell the probe which profile it's testing (VSOCK_ONLY=1 builds have no TCP/IP at all).
if grep -q "^# CONFIG_INET is not set" "$OUT/.config"; then
  sed -i 's|"boot_args": "\([^"]*\)"|"boot_args": "\1 probe_profile=vsock"|' "$cfg"
fi
rm -f "$OUT/vsock-test.sock"
# The same tightened seccomp filter every launch uses, so this test also proves it lets a VM boot and run.
"$ROOT/scripts/seccomp-filter.sh" >/dev/null
note "booting probe guest"
timeout 120 "$FC" --no-api --config-file "$cfg" --seccomp-filter "$OUT/seccomp-filter.bpf" </dev/null 2>&1 | tr -d '\r' > "$OUT/test.log" || true
rm -f "$OUT/vsock-test.sock"

grep -E '^(PASS|FAIL|INFO|SURFACE) ' "$OUT/test.log" || true
grep -E '^PROBE: ' "$OUT/test.log" || true
grep -q 'Kernel panic' "$OUT/test.log" && die "guest panicked; see $OUT/test.log"
grep -q '^PROBE-EXIT=0$' "$OUT/test.log" || die "probe failed or did not finish; see $OUT/test.log"
grep -q '^PROBE-JAILED-EXIT=0$' "$OUT/test.log" || die "jailed probe failed or did not finish; see $OUT/test.log"
# Each pass must run at least this many checks: a section that silently stops running (a setup
# step failing before its checks) shows up as a lower count, not as a pass. Raise these when adding checks.
min_root=96 min_user=83 min_jailed=30
grep -q "^# CONFIG_INET is not set" "$OUT/.config" && min_jailed=28
for pass in root:$min_root user:$min_user jailed:$min_jailed; do
  n="$(sed -n "s/^PROBE: ${pass%%:*} \([0-9]*\) passed.*/\1/p" "$OUT/test.log")"
  [[ -n "$n" && "$n" -ge "${pass##*:}" ]] || die "probe ${pass%%:*} pass ran ${n:-0} checks, expected at least ${pass##*:}; see $OUT/test.log"
done
echo "test: ok"

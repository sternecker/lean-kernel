#!/usr/bin/env bash
# Which syscalls does the built kernel have? Static read of out/vmlinux's syscall table; no boot.
# Writes out/syscalls.txt. Runtime behaviour (what the agent can actually reach) is make test.
source "$(dirname "$0")/_env.sh"

[[ -f "$OUT/vmlinux" && -f "$OUT/System.map" ]] || die "no out/vmlinux; run make build"
python3 -I "$ROOT/scripts/syscalls.py" "$OUT/vmlinux" "$OUT/System.map" \
  "$SRC/arch/x86/entry/syscalls/syscall_64.tbl" "$OUT/syscalls.txt"

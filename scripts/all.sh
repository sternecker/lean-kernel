#!/usr/bin/env bash
# Run every make step that needs no input and spends no tokens, in order, and stop at the first failure:
#
#   deps fetch config build check syscalls rootfs test agent-rootfs agent-test
#
# then print how long each step took. Not run: `make run` and `make agent` (interactive; `make agent`
# also spends tokens) and `make clean`/`distclean`.
#
#   scripts/all.sh                 the default profile, out/
#   scripts/all.sh --vsock         also the vsock-only profile in out-vsock/: config build check test
#   scripts/all.sh --no-agent      stop after the kernel steps (no agent image, no agent self-test)
#
# Settings the steps read pass straight through: LLVM=0 (gcc build), JAIL=0 (agent-test unjailed),
# LEAN_OUT, JOBS. `make deps` only reports missing packages; here a missing package fails the run.
# agent-test runs jailed by default: after editing scripts/lean-agent-jail, rerun
# `sudo scripts/jail-setup.sh` first, or the run stops there with that instruction.
source "$(dirname "$0")/_env.sh"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
vsock=0
agent=1
for a in "$@"; do
  case "$a" in
    --vsock) vsock=1 ;;
    --no-agent) agent=0 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $a" >&2; usage 2 ;;
  esac
done

results=()
started=$SECONDS
summary() {
  echo
  echo "== summary ($(( SECONDS - started ))s)"
  printf '  %s\n' "${results[@]}"
}
# run_step LABEL COMMAND...: run it, record ok/FAIL and its time, stop the whole run on failure.
run_step() {
  local label="$1" t0=$SECONDS
  shift
  note "[$label]"
  if "$@"; then
    results+=("$(printf 'ok    %-22s %5ss' "$label" $(( SECONDS - t0 )))")
  else
    results+=("$(printf 'FAIL  %-22s %5ss' "$label" $(( SECONDS - t0 )))")
    summary
    die "$label failed; fix it, then rerun (finished steps are quick to repeat)"
  fi
}
# make deps exits 0 with packages missing; that is a failure here.
deps() {
  local out
  out="$(make -s -C "$ROOT" deps 2>&1)" || { echo "$out"; return 1; }
  echo "$out"
  ! grep -q '^missing:' <<< "$out"
}

run_step deps deps
for step in fetch config build check syscalls rootfs test; do
  run_step "$step" make -s -C "$ROOT" "$step"
done
if [[ $agent == 1 ]]; then
  run_step agent-rootfs make -s -C "$ROOT" agent-rootfs
  run_step agent-test make -s -C "$ROOT" agent-test
fi
if [[ $vsock == 1 ]]; then
  # The vsock-only kernel has no TCP/IP, so the agent image (which needs loopback) isn't built for it.
  for step in config build check test; do
    run_step "vsock: $step" env VSOCK_ONLY=1 LEAN_OUT="$ROOT/out-vsock" make -s -C "$ROOT" "$step"
  done
fi
summary
echo "all: ok"

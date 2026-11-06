#!/usr/bin/env bash
# Boot Claude Code in an agent VM: out/bzImage + out/rootfs-agent.ext4 (read-only) + a fresh scratch
# drive for /home/agent, with scripts/api-proxy.py on the host holding the credential.
#
#   make agent                         interactive: a bash shell on this terminal, run `claude`
#   TASK='...' make agent              headless: `claude -p "$TASK"`, output here and in out/agent.log
#     TOOLS='Bash Read'                tools allowed without asking in headless mode (default: Bash)
#   TOKEN_FILE=...                     default ~/.config/lean-kernel/oauth-token (chmod 600), from `claude setup-token`
#   AGENT_MAX_REQUESTS=500 AGENT_MAX_INPUT_TOKENS=50000000 AGENT_MAX_OUTPUT_TOKENS=1000000 AGENT_RPM=60
#                                      per-session proxy budget (0 = unlimited); AGENT_MODELS='claude-sonnet-*,...'
#                                      limits models. Usage and totals: out/agent-proxy.log
#   AGENT_SELFTEST=1 (make agent-test)  boot the agent image, check its hardening, no Claude Code, no tokens
#   AGENT_STRACE=1                     trace agent + bridge syscalls (image built with STRACE=1 make agent-rootfs)
#   AGENT_EXEC=1                       allow exec on /tmp and /home/agent (default noexec)
#   KEEP_SCRATCH=1                     start from out/scratch-agent.ext4 and save the home back to it
#                                      (one KEEP_SCRATCH run at a time; without it, the home is discarded)
#   JAIL=1|0|auto                      1 (default): require the jailer (sudo scripts/jail-setup.sh once).
#                                      0: run Firecracker and the proxy as you, unjailed (explicit opt-out).
#                                      auto: jailer if installed, else unjailed, with a warning.
#
# Runs can overlap: each one works in its own out/runs/<id>/ (VM config, vsock socket, scratch drive,
# agent.log, agent-proxy.log, strace summaries). out/runs/latest, out/agent.log and out/agent-proxy.log
# point at the newest run. The newest 20 run directories are kept.
#
# The token stays in the proxy process. The guest gets a placeholder; Firecracker runs without it in its env.
# Jailed (sudo scripts/jail-setup.sh once): Firecracker runs as a uid of its own per run in a chroot, an empty network
# namespace and its own cgroup; the proxy as lean-proxy. TOKEN_FILE then comes from /etc/lean-agent.conf.
source "$(dirname "$0")/_env.sh"

AGENT_UID="${AGENT_UID:-10000}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/lean-kernel/oauth-token}"
WRAPPER=/usr/local/sbin/lean-agent-jail
KEEP_RUNS=20
# Fails closed: a missing wrapper stops the run instead of quietly running Firecracker and the proxy
# as you, with your files and your network.
case "${JAIL:-1}" in
  auto) jailed=0; [[ -x "$WRAPPER" ]] && jailed=1
        [[ $jailed == 1 ]] || echo "warning: $WRAPPER not installed; running UNJAILED (JAIL=auto)" >&2 ;;
  1)    [[ -x "$WRAPPER" ]] || die "$WRAPPER is not installed; run: sudo scripts/jail-setup.sh (or JAIL=0 to run unjailed, as you)"; jailed=1 ;;
  0)    jailed=0 ;;
  *)    die "JAIL must be auto, 1 or 0" ;;
esac
# A wrapper installed before per-run directories reads the shared out/ paths; refuse it rather than
# run two VMs on one set of files.
[[ $jailed == 0 ]] || grep -q '^    run=\*)' "$WRAPPER" \
  || die "the installed $WRAPPER predates per-run directories; rerun: sudo scripts/jail-setup.sh"
[[ $jailed == 1 || -x "$FC" ]] || die "firecracker missing; run make deps"
[[ -f "$OUT/bzImage" ]] || die "no out/bzImage; run make build"
[[ -f "$OUT/rootfs-agent.ext4" ]] || die "no out/rootfs-agent.ext4; run make agent-rootfs"
[[ -f "$TOKEN_FILE" ]] || die "no token at $TOKEN_FILE. Run: claude setup-token, then save the token there with chmod 600 (or set TOKEN_FILE)"

# This run's directory. The id ends in this script's pid, which is how pruning tells a live run from
# a finished one; lean-agent-jail accepts only this exact shape.
run_id="agent-$(date +%Y%m%d-%H%M%S)-$$"
RUN="$OUT/runs/$run_id"
mkdir -p "$OUT/runs"
mkdir -m 0700 "$RUN"
scratch="$RUN/scratch.ext4"
saved="$OUT/scratch-agent.ext4"
keep="${KEEP_SCRATCH:-0}"
vsock="$RUN/v.sock"
proxy=""
cleanup_tty=""
# On any exit: restore the terminal, stop an unjailed proxy, remove this run's sockets, and either save
# the home (KEEP_SCRATCH=1, while this run still holds the lock) or discard it. Logs stay in $RUN.
finish() {
  local rc=$?
  if [[ -n "$cleanup_tty" ]]; then
    stty "$cleanup_tty"
    # Discard terminal replies to the guest's last queries that arrive after the VM is gone, so the
    # host shell doesn't read them as typed input.
    python3 -I -c 'import termios, time; time.sleep(0.3); termios.tcflush(0, termios.TCIFLUSH)' || true
  fi
  [[ -n "$proxy" ]] && { kill "$proxy" 2>/dev/null; wait "$proxy" 2>/dev/null || true; }
  rm -f -- "$vsock" "${vsock}_8080"
  if [[ -s "$scratch" && "$keep" == 1 && -n "${have_lock:-}" ]]; then
    mv -f -- "$scratch" "$saved"
  else
    rm -f -- "$scratch"
  fi
  exit "$rc"
}
trap finish EXIT

# out/agent.log and out/agent-proxy.log, which the docs and older habits use, follow the newest run.
# A regular file left from before per-run directories is kept under a new name, not deleted.
ln -sfn "$run_id" "$OUT/runs/latest"
for f in agent.log agent-proxy.log; do
  if [[ ! -L "$OUT/$f" ]]; then
    [[ -e "$OUT/$f" ]] && mv -f -- "$OUT/$f" "$OUT/$f.pre-runs"
    ln -s "runs/latest/$f" "$OUT/$f"
  fi
done

# Older run directories: keep the newest KEEP_RUNS, never one whose run-agent.sh is still running.
prune_runs() {
  local d pid
  find "$OUT/runs" -mindepth 1 -maxdepth 1 -type d -name 'agent-*' -printf '%f\n' | sort -r | tail -n +$((KEEP_RUNS + 1)) |
  while read -r d; do
    [[ "$d" =~ ^agent-[0-9]{8}-[0-9]{6}-([0-9]+)$ ]] || continue
    pid="${BASH_REMATCH[1]}"
    [[ -d "/proc/$pid" ]] && continue
    rm -r -- "${OUT:?}/runs/$d"
  done
}
prune_runs

# The scratch drive: a fresh home, or (KEEP_SCRATCH=1) a copy of the saved one, which goes back at the
# end. The saved home is locked for the whole run, so two KEEP_SCRATCH runs can't each overwrite the
# other's work.
if [[ "$keep" == 1 ]]; then
  exec 8>"$OUT/.scratch-agent.lock"
  flock -n 8 || die "another KEEP_SCRATCH=1 run is using $saved; wait for it, or run without KEEP_SCRATCH"
  have_lock=1
fi
if [[ "$keep" == 1 && -f "$saved" ]]; then
  cp --sparse=always -- "$saved" "$scratch"
else
  s="$RUN/stage"
  mkdir -p "$s"
  # Skip first-run onboarding and the folder-trust prompt for the agent's home.
  printf '{"hasCompletedOnboarding":true,"theme":"dark","projects":{"/home/agent":{"hasTrustDialogAccepted":true}}}\n' > "$s/.claude.json"
  fakeroot -- sh -c "chown -R $AGENT_UID:$AGENT_UID '$s' && chmod 700 '$s' && /sbin/mkfs.ext4 -q -L agent-home -E root_owner=${AGENT_UID}:${AGENT_UID} -d '$s' '$scratch' ${SCRATCH_MB:-512}M"
  rm -r -- "$s"
fi

# The task drive (/dev/vdc in the guest): raw bytes, no filesystem, written fresh each run, so a
# KEEP_SCRATCH home never carries an old task. Line 1 the allowed tools, then the task, NUL-padded to a
# 4 KiB multiple (a block device is whole sectors; the guest strips the NULs). Raw on purpose: the host
# never parses anything the guest wrote, which editing .task inside the saved ext4 home would mean.
task_img="$RUN/task.img"
{ printf '%s\n' "${TOOLS:-Bash}"; printf '%s' "${TASK:-}"; } > "$task_img"
truncate -s %4096 "$task_img"

# Guest output shown on this terminal: drop control characters (C0 except tab and newline, DEL, C1),
# so nothing the guest prints can send escape sequences to the host's terminal emulator, and the
# bidi/format controls (U+061C, U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, U+FEFF) that reorder or
# hide text on screen.
sanitize() {
  python3 -I -c 'import re, sys
sys.stdout.write(re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f؜​-‏‪-‮⁦-⁩﻿]", "", sys.stdin.buffer.read().decode("utf-8", "replace")))'
}
log="$RUN/agent.log"
plog="$RUN/agent-proxy.log"
# Jailed: Firecracker's own stderr (jailer errors, VMM errors), kept off the terminal and shown stripped.
fclog="$RUN/firecracker.log"
show_fclog() { [[ -s "$fclog" ]] && { echo "--- firecracker ---"; tail -n 20 "$fclog" | sanitize; }; return 0; }
# The guest's exit status: the last AGENT-EXIT line init printed (agent lines are prefixed "| ").
agent_exit() { grep '^AGENT-EXIT=' "$log" | tail -n 1; }

mode=interactive; [[ -n "${TASK:-}" ]] && mode=headless
[[ "${AGENT_SELFTEST:-0}" == "1" ]] && mode=selftest
rows=40 cols=120
if [[ -t 0 ]]; then read -r rows cols < <(stty size) || true; fi
# Unix socket paths are limited to 107 bytes; Firecracker adds _8080 to this one.
(( ${#vsock} + 5 <= 107 )) || die "socket path ${vsock}_8080 is too long for a Unix socket; use a shorter LEAN_OUT"
cfg="$RUN/vm-agent.json"
sed -e "s|@KERNEL@|$OUT/bzImage|" -e "s|@ROOTFS@|$OUT/rootfs-agent.ext4|" -e "s|@VSOCK@|$vsock|" \
    "$ROOT/vm/vm.json.in" > "$cfg"
python3 - "$cfg" "$scratch" "$task_img" "$mode" "$rows" "$cols" "${TERM:-xterm-256color}" "${AGENT_EXEC:-0}" "${AGENT_STRACE:-0}" <<'EOF'
import json, sys
p, scratch, task_img, mode, rows, cols, term, agent_exec, agent_strace = sys.argv[1:]
c = json.load(open(p))
b = c["boot-source"]
b["boot_args"] = b["boot_args"].replace(" rw ", " ro ") + \
    f" agent_mode={mode} agent_exec={agent_exec} agent_strace={agent_strace} agent_rows={rows} agent_cols={cols} agent_term={term}"
if mode == "interactive":  # keep boot messages off the raw terminal; out/agent.log has them in headless mode
    b["boot_args"] += " quiet"
c["drives"][0]["is_read_only"] = True
c["drives"].append({"drive_id": "scratch", "path_on_host": scratch,
                    "is_root_device": False, "is_read_only": False})
c["drives"].append({"drive_id": "task", "path_on_host": task_img,
                    "is_root_device": False, "is_read_only": True})
c["machine-config"]["mem_size_mib"] = 2048
json.dump(c, open(p, "w"), indent=2)
EOF

budget=(max-requests="${AGENT_MAX_REQUESTS:-500}" max-input-tokens="${AGENT_MAX_INPUT_TOKENS:-50000000}"
        max-output-tokens="${AGENT_MAX_OUTPUT_TOKENS:-1000000}" rpm="${AGENT_RPM:-60}" models="${AGENT_MODELS:-}")
if [[ $jailed == 1 ]]; then
  # Same VM, with paths as Firecracker sees them inside the chroot lean-agent-jail builds.
  python3 - "$cfg" "$RUN/vm-jail.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
c["boot-source"]["kernel_image_path"] = "bzImage"
c["drives"][0]["path_on_host"] = "rootfs.ext4"
c["drives"][1]["path_on_host"] = "scratch.ext4"
c["drives"][2]["path_on_host"] = "task.img"
c["vsock"]["uds_path"] = "v.sock"
json.dump(c, open(sys.argv[2], "w"), indent=2)
EOF
  launch=(sudo -n "$WRAPPER" run="$run_id" "${budget[@]}")
  where="jailed: Firecracker as a per-run uid, proxy as lean-proxy"
else
  python3 -I "$ROOT/scripts/api-proxy.py" --listen "${vsock}_8080" --token-file "$TOKEN_FILE" \
    "${budget[@]/#/--}" 2>>"$plog" &
  proxy=$!
  for _ in $(seq 50); do [[ -S "${vsock}_8080" ]] && break; sleep 0.1; done
  [[ -S "${vsock}_8080" ]] || die "api-proxy did not start; see $plog"
  launch=(env -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN "$FC" --no-api --level Error --config-file "$cfg")
  where="unjailed: Firecracker and the proxy run as $(id -un) (sudo scripts/jail-setup.sh to jail them)"
fi

if [[ "$mode" == headless || "$mode" == selftest ]]; then
  if [[ "$mode" == selftest ]]; then note "agent VM self-test ($where): hardening checks, no tokens spent; run $run_id"
  else note "headless agent VM ($where); run $run_id; task: $TASK"; fi
  timeout "${TIMEOUT:-600}" "${launch[@]}" </dev/null 2>&1 | tr -d '\r' > "$log" || true
  sed -n '/^AGENT-START$/,/^AGENT-EXIT=/p' "$log" | sed '1d; s/^| //' | sanitize
  for f in agent socat; do  # AGENT_STRACE=1: syscall summaries, traced from outside the jail
    grep -q "^STRACE-BEGIN $f\$" "$log" || continue
    sed -n "/^STRACE-BEGIN $f\$/,/^STRACE-END\$/p" "$log" | sed '1d;$d' > "$RUN/strace-$f.txt"
    echo "syscall summary: $RUN/strace-$f.txt"
  done
  denials="$(sed -n '/^DENIALS-BEGIN$/,/^DENIALS-END$/p' "$log" | sed '1d;$d')"
  if [[ -n "$denials" ]]; then echo "--- refused by jail-exec (seccomp type=1326, Landlock type=1423) ---"; echo "$denials" | sanitize; fi
  echo "--- proxy log ---"; tail -n 20 "$plog" 2>/dev/null | sanitize
  show_fclog
  # Printed by init after the agent exits: whether Claude Code loaded the image's managed settings.
  grep -m1 '^MANAGED-HOOKS=' "$log" | sed 's/^/managed settings: /; s/MANAGED-HOOKS=//' || true   # absent in selftest mode
  grep -q 'Kernel panic' "$log" && die "guest panicked; see $log"
  if [[ "$mode" == selftest ]]; then
    [[ "$(agent_exit)" == AGENT-EXIT=0 ]] || die "agent self-test failed (SELFTEST FAIL lines above); see $log"
    echo "agent-test: ok ($(grep -c '^SELFTEST PASS' "$log") checks)"
    exit 0
  fi
  [[ "$(agent_exit)" == AGENT-EXIT=0 ]] || die "agent failed or did not finish; see $log"
  echo "agent: ok"
else
  note "interactive agent VM ($where); run $run_id; proxy log: $plog"
  # Raw host terminal: keystrokes reach the guest one by one and unchanged. In cooked mode the host
  # tty buffers input until Enter and turns Enter (CR) into LF, which Claude Code reads as
  # "newline in the prompt", not "submit"; ctrl-c would also kill Firecracker instead of reaching
  # the guest. To get out of a hung guest, kill firecracker from another terminal.
  if [[ -t 0 ]]; then
    cleanup_tty="$(stty -g)"
    stty raw -echo
  fi
  # The serial console goes through scripts/console-filter.py: escape sequences Claude Code's interface
  # needs pass, and the ones that reach past the screen (OSC 52 clipboard write/read, hyperlinks,
  # title reports, DCS/APC strings, window moves) are dropped. Keystrokes go to the guest unfiltered.
  "${launch[@]}" | python3 -I "$ROOT/scripts/console-filter.py"
  [[ -n "$cleanup_tty" ]] && stty "$cleanup_tty"   # cooked again for the tail below; finish() restores and flushes too
  show_fclog
fi

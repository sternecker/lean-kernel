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
#   KEEP_SCRATCH=1                     reuse out/scratch-agent.ext4 instead of starting from an empty home
#   JAIL=auto|1|0                      auto (default): use the jailer if scripts/jail-setup.sh installed it.
#                                      1: require it. 0: run Firecracker and the proxy as you, unjailed.
#
# The token stays in the proxy process. The guest gets a placeholder; Firecracker runs without it in its env.
# Jailed (sudo scripts/jail-setup.sh once): Firecracker runs as lean-fc in a chroot, an empty network
# namespace and its own cgroup; the proxy as lean-proxy. TOKEN_FILE then comes from /etc/lean-agent.conf.
source "$(dirname "$0")/_env.sh"

AGENT_UID="${AGENT_UID:-10000}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/lean-kernel/oauth-token}"
WRAPPER=/usr/local/sbin/lean-agent-jail
case "${JAIL:-auto}" in
  auto) jailed=0; [[ -x "$WRAPPER" ]] && jailed=1 ;;
  1)    [[ -x "$WRAPPER" ]] || die "JAIL=1 but $WRAPPER is not installed; run: sudo scripts/jail-setup.sh"; jailed=1 ;;
  0)    jailed=0 ;;
  *)    die "JAIL must be auto, 1 or 0" ;;
esac
[[ $jailed == 1 || -x "$FC" ]] || die "firecracker missing; run make deps"
[[ -f "$OUT/bzImage" ]] || die "no out/bzImage; run make build"
[[ -f "$OUT/rootfs-agent.ext4" ]] || die "no out/rootfs-agent.ext4; run make agent-rootfs"
[[ -f "$TOKEN_FILE" ]] || die "no token at $TOKEN_FILE. Run: claude setup-token, then save the token there with chmod 600 (or set TOKEN_FILE)"

scratch="$OUT/scratch-agent.ext4"
if [[ "${KEEP_SCRATCH:-0}" != "1" || ! -f "$scratch" ]]; then
  s="$WORK/scratch-agent-stage"
  rm -rf "$s"; mkdir -p "$s"
  # Skip first-run onboarding and the folder-trust prompt for the agent's home.
  printf '{"hasCompletedOnboarding":true,"theme":"dark","projects":{"/home/agent":{"hasTrustDialogAccepted":true}}}\n' > "$s/.claude.json"
  printf '%s\n' "${TASK:-}" > "$s/.task"
  printf '%s\n' "${TOOLS:-Bash}" > "$s/.tools"
  rm -f "$scratch"
  fakeroot -- sh -c "chown -R $AGENT_UID:$AGENT_UID '$s' && chmod 700 '$s' && /sbin/mkfs.ext4 -q -L agent-home -E root_owner=${AGENT_UID}:${AGENT_UID} -d '$s' '$scratch' ${SCRATCH_MB:-512}M"
fi

mode=interactive; [[ -n "${TASK:-}" ]] && mode=headless
[[ "${AGENT_SELFTEST:-0}" == "1" ]] && mode=selftest
rows=40 cols=120
if [[ -t 0 ]]; then read -r rows cols < <(stty size) || true; fi
vsock="$OUT/vsock-agent.sock"
cfg="$OUT/vm-agent.json"
sed -e "s|@KERNEL@|$OUT/bzImage|" -e "s|@ROOTFS@|$OUT/rootfs-agent.ext4|" -e "s|@VSOCK@|$vsock|" \
    "$ROOT/vm/vm.json.in" > "$cfg"
python3 - "$cfg" "$scratch" "$mode" "$rows" "$cols" "${TERM:-xterm-256color}" "${AGENT_EXEC:-0}" "${AGENT_STRACE:-0}" <<'EOF'
import json, sys
p, scratch, mode, rows, cols, term, agent_exec, agent_strace = sys.argv[1:]
c = json.load(open(p))
b = c["boot-source"]
b["boot_args"] = b["boot_args"].replace(" rw ", " ro ") + \
    f" agent_mode={mode} agent_exec={agent_exec} agent_strace={agent_strace} agent_rows={rows} agent_cols={cols} agent_term={term}"
if mode == "interactive":  # keep boot messages off the raw terminal; out/agent.log has them in headless mode
    b["boot_args"] += " quiet"
c["drives"][0]["is_read_only"] = True
c["drives"].append({"drive_id": "scratch", "path_on_host": scratch,
                    "is_root_device": False, "is_read_only": False})
c["machine-config"]["mem_size_mib"] = 2048
json.dump(c, open(p, "w"), indent=2)
EOF

budget=(max-requests="${AGENT_MAX_REQUESTS:-500}" max-input-tokens="${AGENT_MAX_INPUT_TOKENS:-50000000}"
        max-output-tokens="${AGENT_MAX_OUTPUT_TOKENS:-1000000}" rpm="${AGENT_RPM:-60}" models="${AGENT_MODELS:-}")
proxy=""
cleanup_tty=""
trap 'rc=$?; [[ -n "$cleanup_tty" ]] && stty "$cleanup_tty"; [[ -n "$proxy" ]] && { kill $proxy 2>/dev/null; wait $proxy 2>/dev/null || true; }; rm -f "$vsock" "${vsock}_8080"; exit $rc' EXIT
if [[ $jailed == 1 ]]; then
  # Same VM, with paths as Firecracker sees them inside the chroot lean-agent-jail builds.
  python3 - "$cfg" "$OUT/vm-jail.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
c["boot-source"]["kernel_image_path"] = "bzImage"
c["drives"][0]["path_on_host"] = "rootfs.ext4"
c["drives"][1]["path_on_host"] = "scratch.ext4"
c["vsock"]["uds_path"] = "v.sock"
json.dump(c, open(sys.argv[2], "w"), indent=2)
EOF
  launch=(sudo -n "$WRAPPER" "${budget[@]}")
  where="jailed: Firecracker as lean-fc, proxy as lean-proxy"
else
  rm -f "$vsock" "${vsock}_8080"
  python3 "$ROOT/scripts/api-proxy.py" --listen "${vsock}_8080" --token-file "$TOKEN_FILE" \
    "${budget[@]/#/--}" 2>>"$OUT/agent-proxy.log" &
  proxy=$!
  for _ in $(seq 50); do [[ -S "${vsock}_8080" ]] && break; sleep 0.1; done
  [[ -S "${vsock}_8080" ]] || die "api-proxy did not start; see $OUT/agent-proxy.log"
  launch=(env -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN "$FC" --no-api --level Error --config-file "$cfg")
  where="unjailed: Firecracker and the proxy run as $(id -un) (sudo scripts/jail-setup.sh to jail them)"
fi

if [[ "$mode" == headless || "$mode" == selftest ]]; then
  if [[ "$mode" == selftest ]]; then note "agent VM self-test ($where): hardening checks, no tokens spent"
  else note "headless agent VM ($where); task: $TASK"; fi
  timeout "${TIMEOUT:-600}" "${launch[@]}" </dev/null 2>&1 | tr -d '\r' > "$OUT/agent.log" || true
  sed -n '/^AGENT-START$/,/^AGENT-EXIT=/p' "$OUT/agent.log" | sed '1d'
  for f in agent socat; do  # AGENT_STRACE=1: syscall summaries, traced from outside the jail
    grep -q "^STRACE-BEGIN $f\$" "$OUT/agent.log" || continue
    sed -n "/^STRACE-BEGIN $f\$/,/^STRACE-END\$/p" "$OUT/agent.log" | sed '1d;$d' > "$OUT/strace-$f.txt"
    echo "syscall summary: $OUT/strace-$f.txt"
  done
  denials="$(sed -n '/^DENIALS-BEGIN$/,/^DENIALS-END$/p' "$OUT/agent.log" | sed '1d;$d')"
  if [[ -n "$denials" ]]; then echo "--- refused by jail-exec (seccomp type=1326, Landlock type=1423) ---"; echo "$denials"; fi
  echo "--- proxy log ---"; tail -n 20 "$OUT/agent-proxy.log"
  grep -q 'Kernel panic' "$OUT/agent.log" && die "guest panicked; see $OUT/agent.log"
  if [[ "$mode" == selftest ]]; then
    grep -q '^AGENT-EXIT=0$' "$OUT/agent.log" || die "agent self-test failed (SELFTEST FAIL lines above); see $OUT/agent.log"
    echo "agent-test: ok ($(grep -c '^SELFTEST PASS' "$OUT/agent.log") checks)"
    exit 0
  fi
  grep -q '^AGENT-EXIT=0$' "$OUT/agent.log" || die "agent failed or did not finish; see $OUT/agent.log"
  echo "agent: ok"
else
  note "interactive agent VM ($where); proxy log: $OUT/agent-proxy.log"
  # Raw host terminal: keystrokes reach the guest one by one and unchanged. In cooked mode the host
  # tty buffers input until Enter and turns Enter (CR) into LF, which Claude Code reads as
  # "newline in the prompt", not "submit"; ctrl-c would also kill Firecracker instead of reaching
  # the guest. To get out of a hung guest, kill firecracker from another terminal.
  if [[ -t 0 ]]; then
    cleanup_tty="$(stty -g)"
    stty raw -echo
  fi
  "${launch[@]}"
fi

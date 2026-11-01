#!/usr/bin/env bash
# Boot Claude Code in an agent VM: out/bzImage + out/rootfs-agent.ext4 (read-only) + a fresh scratch
# drive for /home/agent, with scripts/api-proxy.py on the host holding the credential.
#
#   make agent                         interactive: a bash shell on this terminal, run `claude`
#   TASK='...' make agent              headless: `claude -p "$TASK"`, output here and in out/agent.log
#     TOOLS='Bash Read'                tools allowed without asking in headless mode (default: Bash)
#   TOKEN_FILE=...                     default ~/.config/lean-kernel/oauth-token (chmod 600), from `claude setup-token`
#   AGENT_EXEC=1                       allow exec on /tmp and /home/agent (default noexec)
#   KEEP_SCRATCH=1                     reuse out/scratch-agent.ext4 instead of starting from an empty home
#
# The token stays in the proxy process. The guest gets a placeholder; Firecracker runs without it in its env.
source "$(dirname "$0")/_env.sh"

AGENT_UID="${AGENT_UID:-10000}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/lean-kernel/oauth-token}"
[[ -x "$FC" ]] || die "firecracker missing; run make deps"
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
rows=40 cols=120
if [[ -t 0 ]]; then read -r rows cols < <(stty size) || true; fi
vsock="$OUT/vsock-agent.sock"
cfg="$OUT/vm-agent.json"
sed -e "s|@KERNEL@|$OUT/bzImage|" -e "s|@ROOTFS@|$OUT/rootfs-agent.ext4|" -e "s|@VSOCK@|$vsock|" \
    "$ROOT/vm/vm.json.in" > "$cfg"
python3 - "$cfg" "$scratch" "$mode" "$rows" "$cols" "${TERM:-xterm-256color}" "${AGENT_EXEC:-0}" <<'EOF'
import json, sys
p, scratch, mode, rows, cols, term, agent_exec = sys.argv[1:]
c = json.load(open(p))
b = c["boot-source"]
b["boot_args"] = b["boot_args"].replace(" rw ", " ro ") + \
    f" agent_mode={mode} agent_exec={agent_exec} agent_rows={rows} agent_cols={cols} agent_term={term}"
if mode == "interactive":  # keep boot messages off the raw terminal; out/agent.log has them in headless mode
    b["boot_args"] += " quiet"
c["drives"][0]["is_read_only"] = True
c["drives"].append({"drive_id": "scratch", "path_on_host": scratch,
                    "is_root_device": False, "is_read_only": False})
c["machine-config"]["mem_size_mib"] = 2048
json.dump(c, open(p, "w"), indent=2)
EOF

rm -f "$vsock" "${vsock}_8080"
python3 "$ROOT/scripts/api-proxy.py" --listen "${vsock}_8080" --token-file "$TOKEN_FILE" \
  2>>"$OUT/agent-proxy.log" &
proxy=$!
trap 'rc=$?; kill $proxy 2>/dev/null; wait $proxy 2>/dev/null || true; rm -f "$vsock" "${vsock}_8080"; exit $rc' EXIT
for _ in $(seq 50); do [[ -S "${vsock}_8080" ]] && break; sleep 0.1; done
[[ -S "${vsock}_8080" ]] || die "api-proxy did not start; see $OUT/agent-proxy.log"

if [[ "$mode" == headless ]]; then
  note "headless agent VM; task: $TASK"
  timeout "${TIMEOUT:-600}" env -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN "$FC" --no-api --config-file "$cfg" \
    </dev/null 2>&1 | tr -d '\r' > "$OUT/agent.log" || true
  sed -n '/^AGENT-START$/,/^AGENT-EXIT=/p' "$OUT/agent.log" | sed '1d'
  echo "--- proxy log ---"; tail -n 20 "$OUT/agent-proxy.log"
  grep -q 'Kernel panic' "$OUT/agent.log" && die "guest panicked; see $OUT/agent.log"
  grep -q '^AGENT-EXIT=0$' "$OUT/agent.log" || die "agent failed or did not finish; see $OUT/agent.log"
  echo "agent: ok"
else
  note "interactive agent VM; proxy log: $OUT/agent-proxy.log"
  # Raw host terminal: keystrokes reach the guest one by one and unchanged. In cooked mode the host
  # tty buffers input until Enter and turns Enter (CR) into LF, which Claude Code reads as
  # "newline in the prompt", not "submit"; ctrl-c would also kill Firecracker instead of reaching
  # the guest. To get out of a hung guest, kill firecracker from another terminal.
  if [[ -t 0 ]]; then
    saved_tty="$(stty -g)"
    trap 'rc=$?; stty "$saved_tty"; kill $proxy 2>/dev/null; wait $proxy 2>/dev/null || true; rm -f "$vsock" "${vsock}_8080"; exit $rc' EXIT
    stty raw -echo
  fi
  env -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN "$FC" --no-api --level Error --config-file "$cfg"
fi

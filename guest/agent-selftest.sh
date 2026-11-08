#!/bin/bash
# agent-selftest: the agent VM's hardening, checked from inside the real agent image (make agent-test).
# Never starts Claude Code and sends nothing the proxy forwards, so it costs no tokens.
#   agent-selftest root    run by init as root: mounts, sysctls, bridge
#   agent-selftest agent   run by init through the agent's own jail-exec policy, as the agent
# Prints "SELFTEST PASS|FAIL <who> <name>: <detail>" lines and exits with the number of failures.
# Run by hand from inside a session (the agent's Bash tool), the agent pass still works, with two differences
# it reports itself: AGENT_UID is not in the environment (defaulted below), and the script runs under the
# tool shell, so the checks on the agent process's own MDWE/JIT posture are skipped with a NOTE line.
who="${1:?root or agent}"
# init exports AGENT_UID. By hand it is unset: default to the owner of the agent's home, the uid the image was
# built for (otherwise the uid and hidepid checks compare against an empty string and fail for no reason).
AGENT_UID="${AGENT_UID:-$(stat -c %u /home/agent 2>/dev/null || echo 10000)}"
fails=0
ok()  { echo "SELFTEST PASS $who $1: $2"; }
bad() { echo "SELFTEST FAIL $who $1: $2"; fails=$((fails + 1)); }
check() { if [ "$2" = 1 ]; then ok "$1" "$3"; else bad "$1" "$3"; fi; }

mount_opts() { awk -v m="$1" '$2 == m { print $4 }' /proc/mounts | tail -n 1; }
has_opt() { case ",$(mount_opts "$1")," in *",$2,"*) echo 1 ;; *) echo 0 ;; esac; }

if [ "$who" = root ]; then
  check "/ mounted ro" "$(has_opt / ro)" "$(mount_opts /)"
  for m in /tmp /home/agent; do
    o="$(mount_opts "$m")"
    want=noexec; [ "$agent_exec" = 1 ] && want=rw
    check "$m nosuid,nodev,$want" "$(( $(has_opt "$m" nosuid) & $(has_opt "$m" nodev) & $(has_opt "$m" "$want") ))" "$o"
  done
  check "/proc hidepid=invisible" "$(has_opt /proc hidepid=invisible)" "$(mount_opts /proc)"
  check "/sys mounted ro" "$(has_opt /sys ro)" "$(mount_opts /sys)"
  # user.max_user_namespaces: USER_NS is compiled out (the probe proves unshare fails), but 6.18 shows the
  # knob regardless, so it is pinned to 0 (vm.json.in) rather than left at a default that reads as "on".
  for s in kernel/kptr_restrict:2 vm/memfd_noexec:2 kernel/dmesg_restrict:1 user/max_user_namespaces:0 \
           fs/protected_symlinks:1 fs/protected_hardlinks:1 fs/protected_fifos:2 fs/protected_regular:2; do
    v="$(cat "/proc/sys/${s%%:*}" 2>&1)"
    check "${s%%:*} = ${s##*:}" "$([ "$v" = "${s##*:}" ] && echo 1 || echo 0)" "$v"
  done
  check "/dev/kmsg mode 600" "$([ "$(stat -c %a /dev/kmsg)" = 600 ] && echo 1 || echo 0)" "mode $(stat -c %a /dev/kmsg)"
  check "bridge listening on 127.0.0.1:8080" "$(grep -q ':1F90 00000000:0000 0A' /proc/net/tcp && echo 1 || echo 0)" "/proc/net/tcp"
  check "/home/agent owned by the agent" "$([ "$(stat -c %u /home/agent)" = "$AGENT_UID" ] && echo 1 || echo 0)" "uid $(stat -c %u /home/agent)"
  # /bin/bash is the W^X launcher (tool-shell.c) unless agent_exec=1 bind-mounted the real bash over it.
  diff -q /bin/bash /bin/bash.real >/dev/null 2>&1 && same=1 || same=0
  if [ "$agent_exec" = 1 ]; then check "/bin/bash is the real bash (agent_exec=1)" "$same" ""
  else check "/bin/bash is the tool-shell launcher" "$((1 - same))" ""; fi
  for s in memory.max:1610612736 memory.oom.group:1 pids.max:512; do
    v="$(cat "/sys/fs/cgroup/agent/${s%%:*}" 2>&1)"
    check "agent cgroup ${s%%:*} = ${s##*:}" "$([ "$v" = "${s##*:}" ] && echo 1 || echo 0)" "$v"
  done
  for f in managed-settings.json managed-mcp.json; do
    check "/etc/claude-code/$f present, root-owned" "$([ -s "/etc/claude-code/$f" ] && [ "$(stat -c %u "/etc/claude-code/$f")" = 0 ] && echo 1 || echo 0)" "$(stat -c '%U %a' "/etc/claude-code/$f" 2>&1)"
  done
  exit "$fails"
fi

# --- as the agent, inside jail-exec ---
# init runs this pass through bash.real, like Claude Code itself, so MDWE is off on entry and the two checks
# on the agent process's own posture (no MDWE, in-process JIT) measure the agent. Started from the Bash tool
# it runs under the tool shell, MDWE is already on, and those two checks would measure the tool shell
# instead: say so once and skip them. make agent-test is where they count.
under_tool_shell=0
if [ "$(jit-probe --get-mdwe 2>/dev/null)" = 1 ]; then
  under_tool_shell=1
  echo "SELFTEST NOTE $who running under the tool shell (PR_GET_MDWE=1 on entry): the agent process's own MDWE and in-process JIT checks are skipped, they would measure the tool shell, not the agent; make agent-test runs them as init does"
fi
check "uid" "$([ "$(id -u)" = "$AGENT_UID" ] && echo 1 || echo 0)" "$(id)"
caps="$(grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status | awk '{print $2}' | sort -u)"
check "no capabilities" "$([ "$caps" = 0000000000000000 ] && echo 1 || echo 0)" "$(echo $caps)"
check "no_new_privs" "$(grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status && echo 1 || echo 0)" ""
check "process limit 512" "$([ "$(ulimit -u)" = 512 ] && echo 1 || echo 0)" "ulimit -u $(ulimit -u)"
check "seccomp filter" "$(grep -q '^Seccomp:[[:space:]]*2' /proc/self/status && echo 1 || echo 0)" ""
others="$(for p in /proc/[0-9]*; do u="$(awk '/^Uid:/{print $2}' "$p/status" 2>/dev/null)"; [ -n "$u" ] && [ "$u" != "$AGENT_UID" ] && echo "${p#/proc/}"; done | wc -l)"
check "sees only its own processes (hidepid)" "$([ "$others" = 0 ] && echo 1 || echo 0)" "$others foreign pids visible"
cg="$(cut -d: -f3 /proc/self/cgroup)"
check "runs in the agent cgroup" "$([ "$cg" = /agent ] && echo 1 || echo 0)" "$cg"
out="$( { echo $$ > /sys/fs/cgroup/cgroup.procs; } 2>&1)"
check "can't leave the agent cgroup" "$([ -n "$out" ] && [ "$(cut -d: -f3 /proc/self/cgroup)" = /agent ] && echo 1 || echo 0)" "${out##*: }"
# Claude Code reads its managed settings as the agent, so they must be readable; the ro root keeps them fixed.
check "can read the managed settings" "$([ -r /etc/claude-code/managed-settings.json ] && grep -q allowManagedHooksOnly /etc/claude-code/managed-settings.json && echo 1 || echo 0)" ""
out="$( { : > /etc/claude-code/managed-settings.json; } 2>&1)"
check "can't change the managed settings" "$([ -n "$out" ] && [ -s /etc/claude-code/managed-settings.json ] && echo 1 || echo 0)" "${out##*: }"

out="$( { cat /dev/kmsg; } 2>&1 | head -n 1)"
check "can't open /dev/kmsg" "$(case "$out" in *"Permission denied"*) echo 1 ;; *) echo 0 ;; esac)" "$out"
# Headless mode's result markers (AGENT-EXIT=, DENIALS-*, MANAGED-HOOKS=) are unforgeable only because every
# byte the agent prints goes through init's "| " prefix: it must have no other path to the serial console.
# init runs this test with the headless fd shape, so jail-exec grants no terminal. /dev/ttyS0 and
# /dev/console are root-only and outside the Landlock /dev rules; /dev/tty needs a controlling terminal,
# which a headless agent (a child of init, which has none) does not have.
for t in /dev/ttyS0 /dev/console /dev/tty; do
  out="$( { : > "$t"; } 2>&1)"
  check "can't write the console via $t" "$([ -n "$out" ] && echo 1 || echo 0)" "${out##*: }"
done
check "no controlling terminal" "$([ ! -t 0 ] && [ ! -t 1 ] && [ ! -t 2 ] && [ -z "$(tty 2>/dev/null | grep -v 'not a tty')" ] && echo 1 || echo 0)" "$(tty 2>&1)"
out="$( { : > /etc/selftest; } 2>&1)"
check "can't write the root fs" "$([ -n "$out" ] && [ ! -e /etc/selftest ] && echo 1 || echo 0)" "$out"
echo x > /home/agent/.selftest 2>/dev/null && rm -f /home/agent/.selftest && w=1 || w=0
check "can write its home" "$w" ""
if [ "$agent_exec" != 1 ]; then
  for d in /tmp /home/agent; do
    cp /bin/true "$d/.selftest-bin" 2>/dev/null
    out="$("$d/.selftest-bin" 2>&1)"; rc=$?
    rm -f "$d/.selftest-bin"
    check "can't run a binary it wrote in $d" "$([ $rc = 126 ] && echo 1 || echo 0)" "exit $rc ${out##*: }"
  done
fi
# Tool shells: Claude Code runs Bash tool commands through /bin/bash, the W^X launcher, so a tool shell
# can't make memory executable, and neither can anything it starts, the real bash included.
if [ "$agent_exec" != 1 ]; then
  out="$(/bin/bash -c 'echo tool-shell-ok' 2>&1)"
  check "tool shell runs" "$([ "$out" = tool-shell-ok ] && echo 1 || echo 0)" "$out"
  # jit-probe tries anonymous RW+mprotect, anonymous RWX, and a MAP_PRIVATE RWX file mapping (the path a
  # MAP_ANONYMOUS-only filter misses); exit 1 means every path was refused.
  out="$(/bin/bash -c jit-probe 2>&1)"; rc=$?
  check "tool shell can't JIT by any path (W^X enforced)" "$([ $rc = 1 ] && echo 1 || echo 0)" "jit-probe exit $rc: $(echo "$out" | tr '\n' ';')"
  /bin/bash -c '/bin/bash.real -c jit-probe' >/dev/null 2>&1; rc=$?
  check "tool shell can't shed W^X via bash.real" "$([ $rc = 1 ] && echo 1 || echo 0)" "jit-probe exit $rc"
  # The kernel-enforced layer (PR_SET_MDWE) is what holds; the seccomp filter is the backstop.
  v="$(/bin/bash -c 'jit-probe --get-mdwe' 2>&1)"
  check "tool shell has MDWE set" "$([ "$v" = 1 ] && echo 1 || echo 0)" "PR_GET_MDWE=$v"
  v="$(/bin/bash -c '/bin/bash.real -c "jit-probe --get-mdwe"' 2>&1)"
  check "MDWE inherited through bash.real" "$([ "$v" = 1 ] && echo 1 || echo 0)" "PR_GET_MDWE=$v"
  if [ $under_tool_shell = 0 ]; then
    v="$(jit-probe --get-mdwe 2>&1)"
    check "agent process itself has no MDWE (it is a JIT; known gap)" "$([ "$v" = 0 ] && echo 1 || echo 0)" "PR_GET_MDWE=$v"
  fi
else
  /bin/bash -c jit-probe >/dev/null 2>&1; rc=$?
  check "tool shell JIT allowed (agent_exec=1)" "$([ $rc = 0 ] && echo 1 || echo 0)" "jit-probe exit $rc"
fi
# KNOWN GAP, asserted so it stays visible and honest: noexec and memfd_noexec stop the agent running a
# binary it wrote to a file or a memfd, but NOT native code Claude Code's own process JITs into anonymous
# memory. jail-exec allows mmap/mprotect with any prot for that process (it must: Claude Code is a Bun/JSC
# JIT), and no kernel option enforces userspace W^X. Tool shells are covered by the launcher above; this
# records the main process. jit-probe returns 0 when JIT works. We record 0 as the expected state; the
# day it flips to 1 the policy changed and this line (and the docs) must be revisited.
if [ $under_tool_shell = 0 ]; then
  jit-probe >/dev/null 2>&1; jrc=$?
  check "in-process JIT works (W^X NOT enforced; known, see HOWTO 9.5)" "$([ $jrc = 0 ] && echo 1 || echo 0)" \
    "jit-probe exit $jrc ($([ $jrc = 0 ] && echo 'anonymous PROT_EXEC allowed' || echo 'blocked/inconclusive -- policy changed, revisit docs'))"
fi

# Socket families: jail-exec's seccomp allows AF_UNIX, AF_INET and AF_INET6 only (--vsock is the bridge's,
# not the agent's). AF_VSOCK is the guest-host channel; AF_NETLINK is kernel configuration surface.
out="$(socat -T1 - VSOCK-CONNECT:2:8080 </dev/null 2>&1)"
check "AF_VSOCK socket refused (seccomp)" "$(case "$out" in *"not permitted"*) echo 1 ;; *) echo 0 ;; esac)" "${out##*: }"
out="$(ip link show 2>&1)"
check "AF_NETLINK socket refused (seccomp)" "$(case "$out" in *"not permitted"*) echo 1 ;; *) echo 0 ;; esac)" "${out##*: }"
# TCP: Landlock allows connect to 8080 only.
out="$( { exec 3<>/dev/tcp/127.0.0.1/9; } 2>&1)"
check "TCP connect to port 9 refused" "$(case "$out" in *"Permission denied"*) echo 1 ;; *) echo 0 ;; esac)" "${out##*: }"

# The proxy: every request here must be refused by the proxy itself, so nothing reaches the API.
http_status() {  # method path body -> HTTP status from the proxy
  exec 3<>/dev/tcp/127.0.0.1/8080 || { echo none; return; }
  printf '%s %s HTTP/1.1\r\nHost: proxy\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "$1" "$2" "${#3}" "$3" >&3
  local line; read -r line <&3; exec 3<&-
  set -- $line; echo "${2:-none}"
}
msg='"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"x"}]'
s="$(http_status GET /v1/models '')"
check "proxy refuses a path off its allowlist" "$([ "$s" = 403 ] && echo 1 || echo 0)" "GET /v1/models -> $s"
s="$(http_status POST /v1/messages "{$msg,\"tools\":[{\"type\":\"web_fetch_20250910\",\"name\":\"web_fetch\"}]}")"
check "proxy refuses server-side web_fetch" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
s="$(http_status POST /v1/messages "{$msg,\"mcp_servers\":[{\"type\":\"url\",\"url\":\"https://example.invalid/mcp\",\"name\":\"x\"}]}")"
check "proxy refuses mcp_servers" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
s="$(http_status POST /v1/messages 'not json')"
check "proxy refuses a non-JSON body" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
# Content the API would fetch server-side: a URL in a source, anywhere in the body, is a way out.
s="$(http_status POST /v1/messages '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.invalid/x.png"}}]}]}')"
check "proxy refuses a URL image source" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
s="$(http_status POST /v1/messages '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"document","source":{"type":"url","url":"https://example.invalid/x.pdf"}}]}]}]}')"
check "proxy refuses a URL document inside a tool result" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
s="$(http_status POST /v1/messages "{$msg,\"some_future_field\":1}")"
check "proxy refuses an unknown top-level field" "$([ "$s" = 403 ] && echo 1 || echo 0)" "-> $s"
# A malformed Content-Length is refused cleanly (once it raised, and the traceback skipped the log cap).
s="$( { exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'POST /v1/messages HTTP/1.1\r\nHost: proxy\r\nContent-Length: abc\r\nConnection: close\r\n\r\n' >&3 && read -r l <&3 && set -- $l && echo "${2:-none}"; } 2>/dev/null )"
check "proxy refuses a malformed Content-Length" "$([ "$s" = 400 ] && echo 1 || echo 0)" "-> ${s:-none}"
exit "$fails"

#!/bin/bash
# agent-selftest: the agent VM's hardening, checked from inside the real agent image (make agent-test).
# Never starts Claude Code and sends nothing the proxy forwards, so it costs no tokens.
#   agent-selftest root    run by init as root: mounts, sysctls, bridge
#   agent-selftest agent   run by init through the agent's own jail-exec policy, as the agent
# Prints "SELFTEST PASS|FAIL <who> <name>: <detail>" lines and exits with the number of failures.
who="${1:?root or agent}"
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
  for s in kernel/kptr_restrict:2 vm/memfd_noexec:2 kernel/dmesg_restrict:1; do
    v="$(cat "/proc/sys/${s%%:*}" 2>&1)"
    check "${s%%:*} = ${s##*:}" "$([ "$v" = "${s##*:}" ] && echo 1 || echo 0)" "$v"
  done
  check "/dev/kmsg mode 600" "$([ "$(stat -c %a /dev/kmsg)" = 600 ] && echo 1 || echo 0)" "mode $(stat -c %a /dev/kmsg)"
  check "bridge listening on 127.0.0.1:8080" "$(grep -q ':1F90 00000000:0000 0A' /proc/net/tcp && echo 1 || echo 0)" "/proc/net/tcp"
  check "/home/agent owned by the agent" "$([ "$(stat -c %u /home/agent)" = "$AGENT_UID" ] && echo 1 || echo 0)" "uid $(stat -c %u /home/agent)"
  exit "$fails"
fi

# --- as the agent, inside jail-exec ---
check "uid" "$([ "$(id -u)" = "$AGENT_UID" ] && echo 1 || echo 0)" "$(id)"
caps="$(grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status | awk '{print $2}' | sort -u)"
check "no capabilities" "$([ "$caps" = 0000000000000000 ] && echo 1 || echo 0)" "$(echo $caps)"
check "no_new_privs" "$(grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status && echo 1 || echo 0)" ""
check "process limit 512" "$([ "$(ulimit -u)" = 512 ] && echo 1 || echo 0)" "ulimit -u $(ulimit -u)"
check "seccomp filter" "$(grep -q '^Seccomp:[[:space:]]*2' /proc/self/status && echo 1 || echo 0)" ""
others="$(for p in /proc/[0-9]*; do u="$(awk '/^Uid:/{print $2}' "$p/status" 2>/dev/null)"; [ -n "$u" ] && [ "$u" != "$AGENT_UID" ] && echo "${p#/proc/}"; done | wc -l)"
check "sees only its own processes (hidepid)" "$([ "$others" = 0 ] && echo 1 || echo 0)" "$others foreign pids visible"

out="$( { cat /dev/kmsg; } 2>&1 | head -n 1)"
check "can't open /dev/kmsg" "$(case "$out" in *"Permission denied"*) echo 1 ;; *) echo 0 ;; esac)" "$out"
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
# KNOWN GAP, asserted so it stays visible and honest: noexec and memfd_noexec stop the agent running a
# binary it wrote to a file or a memfd, but NOT native code it JITs into anonymous memory. jail-exec
# allows mmap/mprotect with any prot (it must: Claude Code is a Bun/JSC JIT), and no kernel option
# enforces userspace W^X, so an in-process JIT (bun:ffi TinyCC, JSC, ctypes, ...) can run agent-written
# code. jit-probe returns 0 when that works. We record 0 as the expected state; the day it flips to 1
# the policy changed and this line (and the docs) must be revisited.
jit-probe >/dev/null 2>&1; jrc=$?
check "in-process JIT works (W^X NOT enforced; known, see HOWTO 9.5)" "$([ $jrc = 0 ] && echo 1 || echo 0)" \
  "jit-probe exit $jrc ($([ $jrc = 0 ] && echo 'anonymous PROT_EXEC allowed' || echo 'blocked/inconclusive -- policy changed, revisit docs'))"

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

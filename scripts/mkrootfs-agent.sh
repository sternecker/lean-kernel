#!/usr/bin/env bash
# Agent root image: out/rootfs-agent.ext4, mounted read-only by scripts/run-agent.sh.
# busybox + bash + socat + the host's Claude Code binary, each with its shared libraries, plus a
# static jail-exec. Built under fakeroot so every file is owned by root (mkfs.ext4 -d copies owners;
# the plain busybox image in mkrootfs.sh does not do this yet). No root privileges needed.
#
# Guest init (below): mounts (writable ones noexec unless AGENT_EXEC=1), loopback up, a jailed socat bridge from 127.0.0.1:8080 to vsock CID 2
# port 8080 (the host's scripts/api-proxy.py), then the agent under jail-exec as AGENT_UID, then reboot.
# Needs the default kernel profile: VSOCK_ONLY=1 removes TCP/IP, including the loopback the bridge uses.
#
# STRACE=1 also puts strace in the image, for AGENT_STRACE=1 make agent: init then traces the agent and
# the bridge from outside the jail and prints which syscalls they made (input for jail-exec's allowlist).
# Claude Code is the version pinned in VERSION (CLAUDE_CODE_VERSION + CLAUDE_CODE_SHA256), taken from the
# host's native install (~/.local/share/claude/versions/<version>) and cached in work/claude-code/ once
# verified, since the installer prunes old versions. When neither has it (a fresh host, or the installer
# pruned it), the pinned version is downloaded from CLAUDE_CODE_URL (the installer's own release URL) and
# accepted only if it matches the pin. CLAUDE_BIN=<path> uses another file; it must still match the pin.
# --pin <version> prints the VERSION lines for a version: the host's copy when installed, otherwise a
# download checked against the release manifest's linux-x64 sha256 (what the installer checks).
source "$(dirname "$0")/_env.sh"

AGENT_UID="${AGENT_UID:-10000}"
size_mb="${AGENT_ROOTFS_MB:-640}"
host_versions="$HOME/.local/share/claude/versions"
[[ -n "${CLAUDE_CODE_URL:-}" ]] || die "VERSION has no CLAUDE_CODE_URL"
# The host binary comes from the installer's linux-x64 (glibc) build, and so do bash and socat in the image.
release_url() { echo "$CLAUDE_CODE_URL/$1/linux-x64/claude"; }
# sha256 the release manifest lists for linux-x64 (the installer's check). Bash regex, as in install.sh:
# [^{}] keeps the match inside the linux-x64 object, and the closing quote keeps linux-x64-musl out.
manifest_sha256() {
  local json; json="$(curl -sSfL "$CLAUDE_CODE_URL/$1/manifest.json")" || return 1
  json="${json//[$'\n\r\t']/}"
  [[ "$json" =~ \"linux-x64\"[[:space:]]*:[[:space:]]*[{][^{}]*\"checksum\"[[:space:]]*:[[:space:]]*\"([a-f0-9]{64})\" ]] || return 1
  echo "${BASH_REMATCH[1]}"
}
# download_release VERSION DEST: fetch the binary to DEST.tmp (caller verifies, then moves it into place).
download_release() {
  note "downloading Claude Code $1 from $(release_url "$1")"
  mkdir -p "$(dirname "$2")"
  curl -sSfL -o "$2.tmp" "$(release_url "$1")" || { rm -f -- "$2.tmp"; die "download failed: $(release_url "$1")"; }
  chmod 755 -- "$2.tmp"  # curl writes 644; the host install is 755
}
if [[ "${1:-}" == "--pin" ]]; then
  v="${2:?usage: $0 --pin <version>}"
  src="$host_versions/$v"
  if [[ ! -f "$src" ]]; then
    src="$WORK/claude-code/$v"
    if [[ ! -f "$src" ]]; then
      want="$(manifest_sha256 "$v")" || die "no release manifest for $v at $CLAUDE_CODE_URL/$v/manifest.json (not a released version?)"
      download_release "$v" "$src"
      echo "$want  $src.tmp" | sha256sum -c --quiet - >/dev/null 2>&1 \
        || { rm -f -- "$src.tmp"; die "downloaded $v does not match the manifest's linux-x64 sha256 $want"; }
      mv -f -- "$src.tmp" "$src"
      echo "verified against the release manifest and cached at $src"
    fi
  fi
  echo "put these in VERSION (then redo the syscall trace, HOWTO 6c):"
  echo "CLAUDE_CODE_VERSION=$v"
  echo "CLAUDE_CODE_SHA256=$(sha256sum "$src" | cut -d' ' -f1)"
  exit 0
fi
[[ "${CLAUDE_CODE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || die "VERSION has no CLAUDE_CODE_SHA256"
cache="$WORK/claude-code/$CLAUDE_CODE_VERSION"
pin_ok() { echo "$CLAUDE_CODE_SHA256  $1" | sha256sum -c --quiet - >/dev/null 2>&1; }
claude_bin=""
for c in ${CLAUDE_BIN:+"$CLAUDE_BIN"} "$cache" "$host_versions/$CLAUDE_CODE_VERSION"; do
  [[ -f "$c" ]] || continue
  if pin_ok "$c"; then claude_bin="$c"; break; fi
  echo "warn: $c does not match CLAUDE_CODE_SHA256; skipping it" >&2
done
if [[ -z "$claude_bin" ]]; then
  # Not on this host (fresh install, or the installer pruned it): fetch the pinned release. The pin is the
  # trust anchor, so a mismatch is fatal, not a warning.
  [[ -n "${CLAUDE_BIN:-}" ]] && die "CLAUDE_BIN=$CLAUDE_BIN does not match CLAUDE_CODE_SHA256"
  download_release "$CLAUDE_CODE_VERSION" "$cache"
  pin_ok "$cache.tmp" || { rm -f -- "$cache.tmp"; die "downloaded Claude Code $CLAUDE_CODE_VERSION does not match CLAUDE_CODE_SHA256 (sha256 $(sha256sum "$cache.tmp" 2>/dev/null | cut -d' ' -f1)); the pin in VERSION and the release disagree"; }
  mv -f -- "$cache.tmp" "$cache"
  claude_bin="$cache"
fi
if [[ "$claude_bin" != "$cache" ]]; then
  mkdir -p "$(dirname "$cache")"; cp -- "$claude_bin" "$cache.tmp" && mv -f -- "$cache.tmp" "$cache"
  claude_bin="$cache"
fi
host_now="$(readlink -f "$(command -v claude 2>/dev/null)" 2>/dev/null || true)"
[[ -n "$host_now" && "$(basename "$host_now")" != "$CLAUDE_CODE_VERSION" ]] \
  && echo "note: the host runs Claude Code $(basename "$host_now"); the image uses the pinned $CLAUDE_CODE_VERSION"
bb="$(command -v busybox)" || die "busybox not installed ($PKG_INSTALL $(pkg busybox-static busybox))"
socat_bin="$(command -v socat)" || die "socat not installed ($PKG_INSTALL socat)"
bash_bin="$(readlink -f /bin/bash)"
grep -q "^# CONFIG_INET is not set" "$OUT/.config" 2>/dev/null \
  && die "out/.config is the vsock-only profile; the agent bridge needs loopback TCP (rebuild without VSOCK_ONLY=1)"

mkdir -p "$OUT"
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/jail-exec" "$ROOT/guest/jail-exec.c"
# A posture probe for agent-selftest: whether the agent can make anonymous memory executable (in-process
# JIT, which noexec and memfd_noexec do not cover). Built like jail-exec; placed on the read-only root.
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/jit-probe" "$ROOT/guest/jit-probe.c"
# The tool shell: /bin/bash is a launcher that loads a W^X seccomp filter and execs /bin/bash.real, so
# a Bash tool command (and anything it starts) can't run the Bun runtime or any other JIT. init starts
# the agent's own shell and Claude Code through bash.real. See guest/tool-shell.c.
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/tool-shell" "$ROOT/guest/tool-shell.c"

stage="$WORK/rootfs-agent-stage"
rm -rf "$stage"
mkdir -p "$stage"/{bin,sbin,etc,proc,sys,dev,tmp,root,home/agent,usr/bin,usr/local/bin}

copy_libs() {  # copy every shared library (and the loader) a binary needs, at the same path
  # A static binary (RHEL's busybox) makes ldd exit 1 with "not a dynamic executable": nothing to copy, not an error.
  { ldd "$1" 2>/dev/null || true; } | awk '/=> \//{print $3} /^\s*\/(lib|lib64|usr)/{print $1}' | while read -r lib; do
    mkdir -p "$stage$(dirname "$lib")"; cp -L "$lib" "$stage$lib"
  done
}
cp "$bb" "$stage/bin/busybox";           copy_libs "$bb"
cp "$bash_bin" "$stage/bin/bash.real";   copy_libs "$bash_bin"
cp "$OUT/tool-shell" "$stage/bin/bash"
cp "$socat_bin" "$stage/usr/bin/socat";  copy_libs "$socat_bin"
install -m 755 "$claude_bin" "$stage/usr/local/bin/claude"; copy_libs "$claude_bin"
cp "$OUT/jail-exec" "$stage/bin/jail-exec"
cp "$OUT/jit-probe" "$stage/bin/jit-probe"
cp "$ROOT/guest/agent-selftest.sh" "$stage/bin/agent-selftest"
if [[ "${STRACE:-0}" == "1" ]]; then
  strace_bin="$(command -v strace)" || die "STRACE=1 but strace is not installed"
  cp "$strace_bin" "$stage/usr/bin/strace"; copy_libs "$strace_bin"
fi
for a in sh mount umount ls cat echo ip mkdir rm cp mv ln chmod touch env id ps dmesg uname cut grep \
         sed awk head tail sort uniq wc tr find xargs sleep date hostname stty setsid tty stat reboot true false \
         printf test which basename dirname readlink tee diff vi less clear; do
  ln -sf busybox "$stage/bin/$a"
done
ln -sf /bin/env "$stage/usr/bin/env"

cat > "$stage/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
agent:x:$AGENT_UID:$AGENT_UID:agent:/home/agent:/bin/bash
EOF
cat > "$stage/etc/group" <<EOF
root:x:0:
nogroup:x:65534:
agent:x:$AGENT_UID:
EOF
printf '127.0.0.1 localhost\n::1 localhost\n' > "$stage/etc/hosts"
echo agent > "$stage/etc/hostname"

# Claude Code's managed settings, on the read-only root: the one settings source the agent can't edit.
# /home/agent/.claude/settings.json and /home/agent/.claude.json are the agent's own files on the scratch
# drive, so hooks, permission rules or MCP servers written there would be the agent widening its own
# policy. Managed settings take precedence over them: hooks from any other source are blocked
# (allowManagedHooksOnly), bypass-permissions mode is refused, WebFetch/WebSearch are denied outright (the
# proxy refuses them anyway, but as a 403 Claude Code shows as a login error), and managed-mcp.json with
# no servers means no MCP server can be configured from any user or project file. Permission rules stay
# with the host (--allowedTools in headless mode, the prompt in interactive mode), so
# allowManagedPermissionRulesOnly is NOT set: it would ignore --allowedTools too. What remains: the agent
# can still add permissions.allow to its own settings. None of the kernel-enforced walls (jail-exec,
# noexec, the proxy) depend on any of this; it keeps the Claude Code policy layer the operator's.
# The SessionStart hook is a control: it writes a marker when Claude Code has loaded these settings and
# run a managed hook, so after a run init can report MANAGED-HOOKS=fired. Without it, a user hook that
# never fires could mean "blocked by allowManagedHooksOnly" or "managed settings never loaded". The
# marker is in the agent's /tmp, so it shows that the settings loaded, not that the agent is honest.
mkdir -p "$stage/etc/claude-code"
cat > "$stage/etc/claude-code/managed-settings.json" <<'EOF'
{
  "allowManagedHooksOnly": true,
  "permissions": {
    "disableBypassPermissionsMode": "disable",
    "deny": ["WebFetch", "WebSearch"]
  },
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "/bin/touch /tmp/.claude-managed-hooks"}]}
    ]
  }
}
EOF
printf '{"mcpServers":{}}\n' > "$stage/etc/claude-code/managed-mcp.json"

# Puts the caller into the agent's cgroup (set up by init), then execs the rest: jail-exec, which drops
# privileges. Root-only: cgroupfs is root-owned and the agent's Landlock ruleset has no write rule on /sys.
cat > "$stage/bin/agent-cgroup" <<'EOF'
#!/bin/sh
echo $$ > /sys/fs/cgroup/agent/cgroup.procs || { echo "agent-cgroup: can't join the agent cgroup" >&2; exit 127; }
exec "$@"
EOF
chmod 755 "$stage/bin/agent-cgroup"

cat > "$stage/init" <<EOF
#!/bin/sh
# Agent VM init. Kernel cmdline key=value params arrive as env vars: agent_mode, agent_exec, agent_strace, agent_rows, agent_cols, agent_term.
export PATH=/usr/local/bin:/usr/bin:/bin
AGENT_UID=$AGENT_UID
EOF
cat >> "$stage/init" <<'EOF'
fail() { echo "AGENT-EXIT=init: $*"; reboot -f; }
# hidepid=invisible: the agent sees only its own processes, not init, socat or other uids.
mount -t proc -o nosuid,nodev,noexec,hidepid=invisible proc /proc || fail "mount /proc"
mount -t sysfs -o ro,nosuid,nodev,noexec sys /sys || fail "mount /sys"
# The agent's cgroup: memory and pids bounded inside the guest as well, so a runaway agent is killed as a
# group (memory.oom.group) before the guest OOM killer has to choose, and init and the bridge keep running
# to report AGENT-EXIT and the denials. The outer limits are the VM's (2 GiB, 2 vCPUs, the fixed-size
# drives) and the host cgroup around Firecracker. /bin/agent-cgroup moves the agent in before jail-exec.
mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup || fail "mount cgroup2"
echo "+memory +pids" > /sys/fs/cgroup/cgroup.subtree_control || fail "cgroup controllers"
mkdir /sys/fs/cgroup/agent || fail "cgroup agent"
echo 1536M > /sys/fs/cgroup/agent/memory.max || fail "cgroup memory.max"
echo 1 > /sys/fs/cgroup/agent/memory.oom.group || fail "cgroup oom.group"
echo 512 > /sys/fs/cgroup/agent/pids.max || fail "cgroup pids.max"
# The kernel mounts devtmpfs on /dev itself (DEVTMPFS_MOUNT); remount it nosuid,noexec.
mount -o remount,nosuid,noexec /dev || fail "remount /dev"
# Kernel log: dmesg_restrict and Landlock already refuse the agent; the node itself root-only as well.
chmod 0600 /dev/kmsg
mkdir -p /dev/pts && mount -t devpts -o nosuid,noexec,mode=620,ptmxmode=666 devpts /dev/pts || fail "mount /dev/pts"
# The only writable places. noexec + vm.memfd_noexec=2 (boot args) leave the agent no way to run a
# binary it wrote: the root fs is read-only and the image has no interpreter that loads native code.
# agent_exec=1 (AGENT_EXEC=1 make agent) lifts it for workloads that build and run code.
wx=noexec; [ "$agent_exec" = 1 ] && wx=exec
mount -t tmpfs -o nosuid,nodev,$wx,mode=1777,size=256m tmp /tmp || fail "mount /tmp"
mount -t ext4 -o nosuid,nodev,$wx /dev/vdb /home/agent || fail "mount scratch drive /dev/vdb"
# agent_exec=1 lifts the tool shells' W^X filter too (a workload that builds and runs code may need a
# JIT in a tool shell): the real bash over the launcher, a bind mount since the root is read-only.
[ "$agent_exec" = 1 ] && { mount -o bind /bin/bash.real /bin/bash || fail "bind bash.real"; }
hostname agent
ip link set lo up || fail "loopback"
[ "$agent_mode" = headless ] && echo 1 > /proc/sys/kernel/printk

# Learning mode (agent_strace=1, image built with STRACE=1): root traces from outside the jail.
T=; TS=
if [ "$agent_strace" = 1 ]; then
  [ -x /usr/bin/strace ] || fail "agent_strace=1 but the image has no strace (STRACE=1 make agent-rootfs)"
  T="/usr/bin/strace -f -qq -c -o /tmp/.strace-agent"; TS="/usr/bin/strace -f -qq -c -o /tmp/.strace-socat"
fi
export T

# localhost:8080 -> host proxy over vsock. Runs as nobody in its own jail: may bind TCP 8080 and use
# vsock, may write nothing, and (--mdwe) can't make memory executable: socat parses what the agent sends
# it, and a compromised socat gets no JIT either.
$TS /bin/jail-exec --bind 8080 --vsock --mdwe 65534 /usr/bin/socat -d0 TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:8080 &
bridge=$!
i=0; while ! grep -q ':1F90 00000000:0000 0A' /proc/net/tcp; do
  i=$((i+1)); [ $i -gt 50 ] && fail "bridge did not start"; sleep 0.1
done

cd /home/agent
umask 077   # inherited by the agent: files it creates are private to it
# The agent's jail, used for the agent and for the self-test alike so the test sees the real policy.
JAIL="/bin/agent-cgroup /bin/jail-exec --rw /home/agent --rw /tmp --connect 8080 $AGENT_UID"
set -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/agent USER=agent LOGNAME=agent SHELL=/bin/bash \
  TERM="${agent_term:-xterm-256color}" LANG=C.UTF-8 \
  ANTHROPIC_BASE_URL=http://127.0.0.1:8080 \
  CLAUDE_CODE_OAUTH_TOKEN=placeholder-real-token-is-added-by-the-host-proxy \
  DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  $JAIL
if [ "$agent_mode" = selftest ]; then
  # make agent-test: hardening checks, no Claude Code, nothing forwarded upstream.
  echo "AGENT-START"
  AGENT_UID=$AGENT_UID agent_exec=$agent_exec /bin/bash.real /bin/agent-selftest root; r1=$?
  # Same fd shape as a headless agent (stdin /dev/null, stdout and stderr a pipe, never the console), so
  # jail-exec grants no terminal and the self-test can check that the console is out of reach.
  set -o pipefail
  env -i PATH=/usr/bin:/bin HOME=/home/agent AGENT_UID=$AGENT_UID agent_exec=$agent_exec \
    $JAIL /bin/bash.real /bin/agent-selftest agent </dev/null 2>&1 | cat; r2=$?
  set +o pipefail
  echo; echo "AGENT-EXIT=$((r1 + r2))"
elif [ "$agent_mode" = headless ]; then
  # The task comes on its own read-only raw drive (/dev/vdc) that the host writes fresh each run: line 1
  # the allowed tools, the rest the task, NUL-padded to whole blocks. Not from /home/agent, which
  # KEEP_SCRATCH=1 carries over from earlier runs. Root reads it here; the agent can't open the device.
  AGENT_TOOLS="$(tr -d '\000' < /dev/vdc | sed -n 1p)"
  AGENT_TASK="$(tr -d '\000' < /dev/vdc | sed 1d)"
  [ -n "$AGENT_TASK" ] || fail "no task on /dev/vdc"
  echo "AGENT-START"
  # Every line the agent prints is prefixed "| ", so none can pose as a marker that run-agent.sh reads
  # from this stream (AGENT-EXIT=, DENIALS-*). Its fds 0-2 are a file and a pipe, never the console:
  # jail-exec grants the terminal on fds 0-2, and the console would let it write unprefixed lines.
  # A process the agent leaves holding the pipe keeps sed waiting; TIMEOUT then ends the run as failed.
  set -o pipefail
  $T "$@" /usr/bin/env AGENT_TASK="$AGENT_TASK" AGENT_TOOLS="$AGENT_TOOLS" \
    /bin/bash.real -c 'claude -p "$AGENT_TASK" --allowedTools "$AGENT_TOOLS" 2>&1' \
    </dev/null 2>&1 | sed 's/^/| /'
  rc=$?; set +o pipefail
  echo; echo "AGENT-EXIT=$rc"   # own line: claude may leave a terminal escape unterminated
else
  # New session with ttyS0 as its controlling terminal (setsid -c), so job control and ctrl-c work.
  # The tty is acquired as root, then inherited across jail-exec's privilege drop.
  export AGENT_UID wx
  setsid -c /bin/sh -c '
    [ -n "$agent_rows" ] && stty rows "$agent_rows" cols "$agent_cols"
    echo
    echo "agent VM: kernel $(uname -r), uid $AGENT_UID, root fs read-only, /home/agent and /tmp $wx"
    echo "run claude. exit powers the VM off."
    echo
    exec $T "$@" /bin/bash.real -l' sh "$@" </dev/ttyS0 >/dev/ttyS0 2>&1 &
  wait $!
fi
# Did Claude Code load the managed settings? Its managed SessionStart hook leaves this marker.
[ "$agent_mode" = selftest ] || echo "MANAGED-HOOKS=$([ -e /tmp/.claude-managed-hooks ] && echo fired || echo not-fired)"
# What the jails refused, from the kernel log (root only: dmesg_restrict). type=1326 is seccomp,
# syscall=N the number; type=1423 is a Landlock denial.
echo "DENIALS-BEGIN"; dmesg | grep -E 'type=(1326|1423)' | tail -n 50; echo "DENIALS-END"
if [ -n "$T" ]; then
  # strace writes its summary once the traced socat processes exit (init is root: hidepid doesn't apply).
  for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = socat ] && kill ${p#/proc/}; done
  wait $bridge
  for f in agent socat; do echo "STRACE-BEGIN $f"; cat /tmp/.strace-$f; echo "STRACE-END"; done
fi
reboot -f
EOF
chmod 755 "$stage/init"

img="$OUT/rootfs-agent.ext4"
rm -f "$img"
fakeroot -- sh -c "chown -R 0:0 '$stage' && chmod -R go-w '$stage' && chmod 1777 '$stage/tmp' && /sbin/mkfs.ext4 -q -L agent-root -d '$stage' '$img' ${size_mb}M"
echo "rootfs: $img (${size_mb} MB, Claude Code $("$claude_bin" --version 2>/dev/null | head -1))"

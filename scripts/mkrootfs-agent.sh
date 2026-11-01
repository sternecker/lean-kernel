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
# verified, since the installer prunes old versions. CLAUDE_BIN=<path> uses another file; it must still
# match the pin. --pin <version> prints the VERSION lines for a host-installed version.
source "$(dirname "$0")/_env.sh"

AGENT_UID="${AGENT_UID:-10000}"
size_mb="${AGENT_ROOTFS_MB:-640}"
host_versions="$HOME/.local/share/claude/versions"
if [[ "${1:-}" == "--pin" ]]; then
  v="${2:?usage: $0 --pin <version>}"
  [[ -f "$host_versions/$v" ]] || die "$host_versions/$v not found; install that version of Claude Code first"
  echo "put these in VERSION (then redo the syscall trace, HOWTO 6c):"
  echo "CLAUDE_CODE_VERSION=$v"
  echo "CLAUDE_CODE_SHA256=$(sha256sum "$host_versions/$v" | cut -d' ' -f1)"
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
[[ -n "$claude_bin" ]] || die "no Claude Code $CLAUDE_CODE_VERSION matching CLAUDE_CODE_SHA256 (looked in ${CLAUDE_BIN:+$CLAUDE_BIN, }$cache, $host_versions/$CLAUDE_CODE_VERSION)"
if [[ "$claude_bin" != "$cache" ]]; then
  mkdir -p "$(dirname "$cache")"; cp -- "$claude_bin" "$cache.tmp" && mv -f -- "$cache.tmp" "$cache"
  claude_bin="$cache"
fi
host_now="$(readlink -f "$(command -v claude 2>/dev/null)" 2>/dev/null || true)"
[[ -n "$host_now" && "$(basename "$host_now")" != "$CLAUDE_CODE_VERSION" ]] \
  && echo "note: the host runs Claude Code $(basename "$host_now"); the image uses the pinned $CLAUDE_CODE_VERSION"
bb="$(command -v busybox)" || die "busybox not installed (apt install busybox-static)"
socat_bin="$(command -v socat)" || die "socat not installed (apt install socat)"
bash_bin="$(readlink -f /bin/bash)"
grep -q "^# CONFIG_INET is not set" "$OUT/.config" 2>/dev/null \
  && die "out/.config is the vsock-only profile; the agent bridge needs loopback TCP (rebuild without VSOCK_ONLY=1)"

mkdir -p "$OUT"
gcc -static -O2 -Wall -Wextra -Werror -o "$OUT/jail-exec" "$ROOT/guest/jail-exec.c"

stage="$WORK/rootfs-agent-stage"
rm -rf "$stage"
mkdir -p "$stage"/{bin,sbin,etc,proc,sys,dev,tmp,root,home/agent,usr/bin,usr/local/bin}

copy_libs() {  # copy every shared library (and the loader) a binary needs, at the same path
  ldd "$1" 2>/dev/null | awk '/=> \//{print $3} /^\s*\/(lib|lib64|usr)/{print $1}' | while read -r lib; do
    mkdir -p "$stage$(dirname "$lib")"; cp -L "$lib" "$stage$lib"
  done
}
cp "$bb" "$stage/bin/busybox";           copy_libs "$bb"
cp "$bash_bin" "$stage/bin/bash";        copy_libs "$bash_bin"
cp "$socat_bin" "$stage/usr/bin/socat";  copy_libs "$socat_bin"
cp "$claude_bin" "$stage/usr/local/bin/claude"; copy_libs "$claude_bin"
cp "$OUT/jail-exec" "$stage/bin/jail-exec"
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
# vsock, may write nothing.
$TS /bin/jail-exec --bind 8080 --vsock 65534 /usr/bin/socat -d0 TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:8080 &
bridge=$!
i=0; while ! grep -q ':1F90 00000000:0000 0A' /proc/net/tcp; do
  i=$((i+1)); [ $i -gt 50 ] && fail "bridge did not start"; sleep 0.1
done

cd /home/agent
umask 077   # inherited by the agent: files it creates are private to it
# The agent's jail, used for the agent and for the self-test alike so the test sees the real policy.
JAIL="/bin/jail-exec --rw /home/agent --rw /tmp --connect 8080 $AGENT_UID"
set -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/agent USER=agent LOGNAME=agent SHELL=/bin/bash \
  TERM="${agent_term:-xterm-256color}" LANG=C.UTF-8 \
  ANTHROPIC_BASE_URL=http://127.0.0.1:8080 \
  CLAUDE_CODE_OAUTH_TOKEN=placeholder-real-token-is-added-by-the-host-proxy \
  DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  $JAIL
if [ "$agent_mode" = selftest ]; then
  # make agent-test: hardening checks, no Claude Code, nothing forwarded upstream.
  echo "AGENT-START"
  AGENT_UID=$AGENT_UID agent_exec=$agent_exec /bin/bash /bin/agent-selftest root; r1=$?
  env -i PATH=/usr/bin:/bin HOME=/home/agent AGENT_UID=$AGENT_UID agent_exec=$agent_exec \
    $JAIL /bin/bash /bin/agent-selftest agent; r2=$?
  echo; echo "AGENT-EXIT=$((r1 + r2))"
elif [ "$agent_mode" = headless ]; then
  echo "AGENT-START"
  $T "$@" /bin/bash -c 'claude -p "$(cat /home/agent/.task)" --allowedTools "$(cat /home/agent/.tools)" </dev/null 2>&1'
  rc=$?; echo; echo "AGENT-EXIT=$rc"   # own line: claude may leave a terminal escape unterminated
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
    exec $T "$@" /bin/bash -l' sh "$@" </dev/ttyS0 >/dev/ttyS0 2>&1 &
  wait $!
fi
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

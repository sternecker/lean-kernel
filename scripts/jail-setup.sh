#!/usr/bin/env bash
# One-time host setup for running the agent VM under Firecracker's jailer. Run it yourself:
#
#   sudo scripts/jail-setup.sh            install, or update after editing scripts/lean-agent-jail
#   sudo scripts/jail-setup.sh uninstall  remove everything it installed
#
# What it changes on the host:
#   users      lean-fc (runs Firecracker), lean-proxy (runs the API proxy): system users, no home,
#              no shell, no password
#   files      /usr/local/lib/lean-agent/{jailer,firecracker}  root-owned copies from the release
#                tarball, re-verified against FIRECRACKER_SHA256 in VERSION. Root must never run the
#                copies in bin/, which the repo owner can write.
#              /usr/local/sbin/lean-agent-jail                 root-owned copy of scripts/lean-agent-jail
#              /etc/lean-agent.conf                            owner, paths, cgroup limits
#              /etc/sudoers.d/lean-agent                       lets OWNER run exactly
#                                                              /usr/local/sbin/lean-agent-jail without a password
#              /srv/lean-agent                                 per-run chroots (created and removed per run)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0 ${*:-}" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNER="${SUDO_USER:-}"
[[ -n "$OWNER" && "$OWNER" != root ]] || { echo "run with sudo from your own account" >&2; exit 1; }
LIB=/usr/local/lib/lean-agent
WRAPPER=/usr/local/sbin/lean-agent-jail
CONF=/etc/lean-agent.conf
SUDOERS=/etc/sudoers.d/lean-agent

if [[ "${1:-install}" == uninstall ]]; then
  rm -f "$WRAPPER" "$SUDOERS" "$CONF"
  rm -f "$LIB/jailer" "$LIB/firecracker"; rmdir "$LIB" 2>/dev/null || true
  rmdir /srv/lean-agent/firecracker /srv/lean-agent 2>/dev/null || true
  rmdir /sys/fs/cgroup/lean-agent 2>/dev/null || true
  for u in lean-fc lean-proxy; do getent passwd "$u" >/dev/null && userdel "$u"; done
  echo "uninstalled"
  exit 0
fi
[[ "${1:-install}" == install ]] || { echo "usage: sudo $0 [install|uninstall]" >&2; exit 2; }

# shellcheck disable=SC1091
source "$ROOT/VERSION"
# The release tarball, under the name deps-check.sh uses or an earlier download's; it must match the pin.
tgz=""
for t in "$ROOT/bin/firecracker-$FIRECRACKER_VERSION-x86_64.tgz" "$ROOT/bin/fc.tgz"; do
  [[ -f "$t" ]] && echo "$FIRECRACKER_SHA256  $t" | sha256sum -c --quiet - 2>/dev/null && { tgz="$t"; break; }
done
[[ -n "$tgz" ]] || { echo "no Firecracker $FIRECRACKER_VERSION tarball in bin/ matching FIRECRACKER_SHA256; run make deps" >&2; exit 1; }
echo "firecracker tarball: $tgz (sha256 ok)"

for u in lean-fc lean-proxy; do
  getent passwd "$u" >/dev/null || useradd --system --user-group --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin --comment "lean-kernel agent jail" "$u"
done

tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT
tar xzf "$tgz" -C "$tmp"
rel="$tmp/release-$FIRECRACKER_VERSION-x86_64"
install -d -o root -g root -m 0755 "$LIB"
install -o root -g root -m 0755 "$rel/jailer-$FIRECRACKER_VERSION-x86_64" "$LIB/jailer"
install -o root -g root -m 0755 "$rel/firecracker-$FIRECRACKER_VERSION-x86_64" "$LIB/firecracker"
install -o root -g root -m 0755 "$ROOT/scripts/lean-agent-jail" "$WRAPPER"

home="$(getent passwd "$OWNER" | cut -d: -f6)"
cat > "$tmp/conf" <<EOF
# Written by scripts/jail-setup.sh. Root-owned: lean-agent-jail refuses to run otherwise.
OWNER=$(printf %q "$OWNER")
REPO=$(printf %q "$ROOT")
OUT=$(printf %q "$ROOT/out")
TOKEN_FILE=$(printf %q "$home/.config/lean-kernel/oauth-token")
# Per-VM cgroup v2 limits. The guest has 2 GiB and 2 vCPUs; this caps the whole Firecracker process.
CGROUPS=1
MEM_MAX=$((2560 * 1024 * 1024))
PIDS_MAX=64
CPU_MAX="200000 100000"
EOF
install -o root -g root -m 0644 "$tmp/conf" "$CONF"

printf '%s ALL=(root) NOPASSWD: %s\n' "$OWNER" "$WRAPPER" > "$tmp/sudoers"
visudo -cqf "$tmp/sudoers" || { echo "generated sudoers rule failed visudo" >&2; exit 1; }
install -o root -g root -m 0440 "$tmp/sudoers" "$SUDOERS"

install -d -o root -g root -m 0711 /srv/lean-agent /srv/lean-agent/firecracker

echo "installed. Checking:"
SUDO_USER="$OWNER" "$WRAPPER" --check

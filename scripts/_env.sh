#!/usr/bin/env bash
# Shared environment for lean-kernel scripts. Source, don't execute.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
set -a; source "$ROOT/VERSION"; set +a

WORK="$ROOT/work"
# LEAN_OUT=<dir> builds somewhere other than out/ (e.g. a second profile: VSOCK_ONLY=1 LEAN_OUT=$PWD/out-vsock).
OUT="${LEAN_OUT:-$ROOT/out}"
BIN="$ROOT/bin"
SRC="$WORK/linux-$KERNEL_VERSION"
FC="$BIN/release-$FIRECRACKER_VERSION-x86_64/firecracker-$FIRECRACKER_VERSION-x86_64"
JOBS="${JOBS:-$(nproc)}"

# LLVM=1 (default) builds with clang + lld and adds llvm.fragment (CFI, RANDSTRUCT, KSTACK_ERASE).
# LLVM=0 is the gcc build, which has none of those. Debian installs versioned LLVMs
# (/usr/lib/llvm-N/bin) without unversioned clang/ld.lld on PATH, so use the newest one that has both.
LLVM="${LLVM:-1}"
MAKE_TOOLCHAIN=()
LLVM_DIR=""
if [[ "$LLVM" == "1" ]]; then
  for d in $(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -t- -k2 -n -r); do
    [[ -x "$d/clang" && -x "$d/ld.lld" ]] && { LLVM_DIR="$d/"; break; }
  done
  MAKE_TOOLCHAIN=(LLVM="${LLVM_DIR:-1}" LLVM_IAS=1)
fi

# Host distro family, decided before anything else runs: debian (Debian, Ubuntu, ...) or rhel (RHEL,
# Fedora, CentOS Stream, Rocky, Alma, ...). It picks the package tool, the package-presence check and the
# package names the scripts print. Detection reads /etc/os-release (ID, then ID_LIKE); LEAN_DISTRO=debian|rhel
# overrides it. Anything else stops here: the scripts have only been exercised on these two families.
DISTRO_FAMILY="${LEAN_DISTRO:-}"
DISTRO_NAME="unknown"
if [[ -r /etc/os-release ]]; then
  DISTRO_NAME="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-${ID:-unknown}}")"
fi
if [[ -z "$DISTRO_FAMILY" ]]; then
  _os_ids=""
  [[ -r /etc/os-release ]] && _os_ids="$(. /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}")"
  for _id in $_os_ids; do
    case "$_id" in
      debian|ubuntu)             DISTRO_FAMILY=debian; break ;;
      rhel|fedora|centos|rocky|almalinux) DISTRO_FAMILY=rhel; break ;;
    esac
  done
  unset _os_ids _id
fi
case "$DISTRO_FAMILY" in
  debian) PKG_INSTALL="sudo apt install"; pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; } ;;
  rhel)   PKG_INSTALL="sudo dnf install"; pkg_installed() { rpm -q "$1" >/dev/null 2>&1; } ;;
  *) echo "error: unsupported or undetected distro ($DISTRO_NAME); lean-kernel supports Debian and RHEL families." >&2
     echo "       set LEAN_DISTRO=debian or LEAN_DISTRO=rhel to force one (see make distro)" >&2
     exit 1 ;;
esac
# pkg DEBIAN_NAME RHEL_NAME: the package name for this host's family (the same name when only one is given).
pkg() { if [[ "$DISTRO_FAMILY" == rhel ]]; then echo "${2:-$1}"; else echo "$1"; fi; }

# VSOCK_ONLY=1 adds vsock-only.fragment: no TCP/IP, no NIC driver in the guest.
VSOCK_ONLY="${VSOCK_ONLY:-0}"

die() { echo "error: $*" >&2; exit 1; }
note() { echo "== $*"; }

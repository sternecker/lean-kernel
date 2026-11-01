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

# VSOCK_ONLY=1 adds vsock-only.fragment: no TCP/IP, no NIC driver in the guest.
VSOCK_ONLY="${VSOCK_ONLY:-0}"

die() { echo "error: $*" >&2; exit 1; }
note() { echo "== $*"; }

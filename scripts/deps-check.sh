#!/usr/bin/env bash
# Report missing build/runtime dependencies and fetch + verify the Firecracker release.
# Never installs packages itself (needs sudo); prints the apt line instead.
source "$(dirname "$0")/_env.sh"

missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$2"); }
need make make; need gcc gcc; need flex flex; need bison bison; need bc bc
need pahole dwarves; need cpio cpio; need curl curl
need /sbin/mkfs.ext4 e2fsprogs
for p in libelf-dev libssl-dev; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
if [[ "$LLVM" == "1" && -z "$LLVM_DIR" ]]; then missing+=(clang-22 lld-22); fi
[[ -n "$LLVM_DIR" ]] && echo "llvm: $LLVM_DIR"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "missing: ${missing[*]}"
  echo "install: sudo apt install ${missing[*]}"
else
  echo "build dependencies: ok"
fi

[[ -c /dev/kvm ]] || die "/dev/kvm not present"
[[ -w /dev/kvm ]] || die "/dev/kvm not writable by $(id -un); add to the kvm group"
echo "kvm: ok"

mkdir -p "$BIN"
tgz="$BIN/firecracker-$FIRECRACKER_VERSION-x86_64.tgz"
if [[ ! -x "$FC" ]]; then
  note "fetching firecracker $FIRECRACKER_VERSION"
  curl -sSL -o "$tgz" "https://github.com/firecracker-microvm/firecracker/releases/download/$FIRECRACKER_VERSION/firecracker-$FIRECRACKER_VERSION-x86_64.tgz"
  echo "$FIRECRACKER_SHA256  $tgz" | sha256sum -c - >/dev/null || die "firecracker sha256 mismatch"
  tar xzf "$tgz" -C "$BIN"
fi
[[ -x "$FC" ]] || die "firecracker binary not found at $FC"
echo "firecracker: $("$FC" --version | head -1)"

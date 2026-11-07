#!/usr/bin/env bash
# Report missing build/runtime dependencies and fetch + verify the Firecracker release.
# Never installs packages itself (needs sudo); prints the apt/dnf line for the detected distro family
# (see make distro) instead.
source "$(dirname "$0")/_env.sh"

missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$2"); }
need make make; need gcc gcc; need flex flex; need bison bison; need bc bc
need pahole dwarves; need cpio cpio; need curl curl
need /sbin/mkfs.ext4 e2fsprogs; need fakeroot fakeroot
for p in "$(pkg libelf-dev elfutils-libelf-devel)" "$(pkg libssl-dev openssl-devel)"; do
  pkg_installed "$p" || missing+=("$p")
done
clang_pkgs=("$(pkg "clang-$CLANG_MIN" clang)" "$(pkg "lld-$CLANG_MIN" lld)")
if [[ "$LLVM" == "1" ]]; then
  # Debian: versioned packages under /usr/lib/llvm-N (_env.sh picks the newest). RHEL family: unversioned
  # clang/lld on PATH. Either way the clang found must be >= CLANG_MIN (VERSION); older ones drop hardening.
  if [[ "$DISTRO_FAMILY" == rhel ]]; then
    command -v clang >/dev/null 2>&1 && command -v ld.lld >/dev/null 2>&1 || missing+=("${clang_pkgs[@]}")
  else
    [[ -n "$LLVM_DIR" ]] || missing+=("${clang_pkgs[@]}")
  fi
  cv="$(clang_major)"
  if [[ -n "$cv" && "$cv" -lt "$CLANG_MIN" ]]; then
    echo "clang: $cv is too old; the LLVM build needs clang >= $CLANG_MIN (have: $(clang_version))"
    [[ "$DISTRO_FAMILY" == rhel ]] && echo "       CentOS Stream 10 / RHEL 10 ship clang 22; older releases need a newer llvm-toolset, or LLVM=0 for gcc"
    missing+=("${clang_pkgs[@]}")
  fi
fi
echo "distro: $DISTRO_NAME ($DISTRO_FAMILY)"
[[ -n "$LLVM_DIR" ]] && echo "llvm: $LLVM_DIR"
[[ "$LLVM" == "1" && -n "$(clang_major)" ]] && echo "clang: $(clang_version) (need >= $CLANG_MIN)"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "missing: ${missing[*]}"
  echo "install: $PKG_INSTALL ${missing[*]}"
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

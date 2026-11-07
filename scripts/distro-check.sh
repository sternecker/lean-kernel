#!/usr/bin/env bash
# Report which distro family the host was detected as (debian or rhel) and which package tool the other
# scripts will name. The detection itself lives in _env.sh, so every make target already stops on an
# unsupported host; this target just shows the result. LEAN_DISTRO=debian|rhel overrides detection.
source "$(dirname "$0")/_env.sh"

echo "distro: $DISTRO_NAME"
echo "family: $DISTRO_FAMILY${LEAN_DISTRO:+ (forced by LEAN_DISTRO)}"
echo "packages: $PKG_INSTALL ..."
[[ "$(uname -m)" == x86_64 ]] || die "x86_64 host required (this is $(uname -m))"
if [[ "$DISTRO_FAMILY" == rhel ]]; then
  echo "note: the build is exercised on Debian 13 and CentOS Stream 10; other RHEL-family hosts get package-name mapping only."
  echo "      The RHEL family ships unversioned clang/lld; the LLVM build needs clang >= $CLANG_MIN (CentOS Stream 10 /"
  echo "      RHEL 10 ship 22; older releases need a newer llvm-toolset), or LLVM=0 for the gcc build."
fi

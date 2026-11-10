#!/usr/bin/env bash
# Print the AI JAIL's version (LEAN_KERNEL_VERSION in VERSION), the commit it was run from, and every pin
# in VERSION, one per line. Paste the output into a bug or security report (SECURITY.md).
#
#   make version
#   scripts/version.sh --short     only the version string, for scripts and tags
source "$(dirname "$0")/_env.sh"

if [[ "${1:-}" == "--short" ]]; then
  echo "$LEAN_KERNEL_VERSION"
  exit 0
fi

commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
dirty=""
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]] || dirty=" (uncommitted changes)"
fi
tag="$(git -C "$ROOT" describe --tags --exact-match 2>/dev/null || true)"

echo "ai-jail:       lean-kernel AI JAIL $LEAN_KERNEL_VERSION"
echo "commit:        $commit$dirty${tag:+ tag $tag}"
echo "kernel:        $KERNEL_VERSION (longterm $KERNEL_SERIES)"
echo "firecracker:   $FIRECRACKER_VERSION"
echo "claude-code:   $CLAUDE_CODE_VERSION"
echo "checker:       $KHC_COMMIT"
echo "base config:   $(basename "$BASE_CONFIG") (fetched $BASE_CONFIG_FETCHED)"
echo "patch set:     ${PATCHSET:-none}"
echo "profile:       llvm=$LLVM vsock_only=$VSOCK_ONLY"

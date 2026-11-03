#!/usr/bin/env bash
# Generate an SBOM for the agent image in SPDX (the Linux Foundation / ISO/IEC 5962:2021 format),
# using Syft. Writes out/agent-sbom.spdx.json, and also out/agent-sbom.cdx.json (CycloneDX) for tools
# that want it.
#
#   make sbom                scan the staging tree (no sudo) if present, else the built image
#   SBOM_TARGET=image        force scanning out/rootfs-agent.ext4 (loop-mount, needs sudo)
#   SBOM_FORMAT='spdx-json'  override the output formats (space- or comma-separated Syft format names)
#
# What this captures: the distro binaries the image bundles (busybox, bash, socat, glibc), found from
# their package metadata. What it does NOT, and why THIRD-PARTY.md is still the source of truth:
#   - the kernel and Firecracker are separate artifacts, not inside the image;
#   - TinyCC and Bun are statically embedded in the Claude Code binary, so no scanner sees them;
#   - Claude Code itself is a single pinned binary under Anthropic's own terms.
source "$(dirname "$0")/_env.sh"

command -v syft >/dev/null 2>&1 || die "syft not installed. Install it (https://github.com/anchore/syft):
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin
or via your package manager (brew install syft), then rerun make sbom"

stage="$WORK/rootfs-agent-stage"
img="$OUT/rootfs-agent.ext4"
out_base="$OUT/agent-sbom"
# Space- or comma-separated Syft format specs; each "name=path" writes that file.
formats="${SBOM_FORMAT:-spdx-json=$out_base.spdx.json cyclonedx-json=$out_base.cdx.json}"

# Build the Syft output args. Default specs carry their own path; a bare format name gets a default one.
out_args=()
for f in ${formats//,/ }; do
  case "$f" in
    *=*) out_args+=(-o "$f") ;;
    *)   out_args+=(-o "$f=$out_base.$f") ;;
  esac
done

target="${SBOM_TARGET:-auto}"
[[ "$target" == auto && -d "$stage" ]] && target=stage
[[ "$target" == auto && -f "$img" ]] && target=image
[[ "$target" == auto ]] && die "nothing to scan: no $stage and no $img. Run: make agent-rootfs"

case "$target" in
  stage)
    [[ -d "$stage" ]] || die "SBOM_TARGET=stage but $stage is missing; run make agent-rootfs"
    note "SBOM: scanning the staging tree $stage (no sudo)"
    syft scan "dir:$stage" "${out_args[@]}"
    ;;
  image)
    [[ -f "$img" ]] || die "SBOM_TARGET=image but $img is missing; run make agent-rootfs"
    command -v sudo >/dev/null 2>&1 || die "scanning the image needs sudo to loop-mount it; install sudo or use the staging tree"
    mnt="$(mktemp -d)"
    # Read-only loop mount, always unmounted and removed on exit.
    cleanup() { sudo umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; }
    trap cleanup EXIT
    note "SBOM: loop-mounting $img read-only (sudo)"
    sudo mount -o ro,loop "$img" "$mnt" || die "could not mount $img"
    syft scan "dir:$mnt" "${out_args[@]}"
    ;;
  *) die "SBOM_TARGET must be auto, stage or image" ;;
esac

echo
note "SBOM written:"
for f in ${formats//,/ }; do echo "  ${f#*=}"; done
echo "Note: the kernel, Firecracker, and the TinyCC/Bun embedded in the Claude Code binary are not"
echo "discoverable by a scanner; see THIRD-PARTY.md for the complete component list."

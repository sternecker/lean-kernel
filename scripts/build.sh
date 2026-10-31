#!/usr/bin/env bash
# Build bzImage -> out/bzImage. Firecracker boots it through the decompressor, which is what randomizes
# the kernel base (KASLR); booting the bare vmlinux ELF skips that. vmlinux and System.map stay in out/
# for decoding oops addresses on the host (no kallsyms in the guest). LLVM=0 for gcc.
source "$(dirname "$0")/_env.sh"

[[ -f "$OUT/.config" ]] || die "no out/.config; run make config"
note "building bzImage with $JOBS jobs$([[ "$LLVM" == 1 ]] && echo ' (LLVM)')"
start=$(date +%s)
( cd "$SRC" && make -s "${MAKE_TOOLCHAIN[@]}" O="$OUT" -j"$JOBS" bzImage )
cp "$OUT/arch/x86/boot/bzImage" "$OUT/bzImage"
echo "build time: $(( $(date +%s) - start ))s"
ls -l "$OUT/bzImage" | awk '{printf "bzImage: %.1f MB\n", $5/1048576}'
# Sanity: the two cuts that matter most, read back from the built kernel's config.
for opt in CONFIG_MODULES CONFIG_IO_URING CONFIG_USER_NS; do
  grep -q "^$opt=y" "$OUT/.config" && die "$opt is on in the built kernel"
done
echo "built: $OUT/bzImage"

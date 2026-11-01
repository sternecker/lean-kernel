#!/usr/bin/env bash
# Build bzImage -> out/bzImage. Firecracker boots it through the decompressor, which is what randomizes
# the kernel base (KASLR); booting the bare vmlinux ELF skips that. vmlinux and System.map stay in out/
# for decoding oops addresses on the host (no kallsyms in the guest). LLVM=0 for gcc.
source "$(dirname "$0")/_env.sh"

[[ -f "$OUT/.config" ]] || die "no out/.config; run make config"
profile="lean"; [[ "$VSOCK_ONLY" == "1" ]] && profile="lean-vsock"
verified="$OUT/$profile-$KERNEL_VERSION.config"
[[ -f "$verified" ]] || die "no $verified (the copy make config verified); run make config"
# The build reruns Kconfig whenever the toolchain differs from the one make config used (another
# compiler, LLVM=0, a newer clang picked up by _env.sh) and can silently drop options that depend
# on it: CFI, RANDSTRUCT, KSTACK_ERASE, LTO. So the built config must be byte-identical to the
# verified one, checked before the build (syncconfig applies the drift in seconds) and after it.
same_as_verified() {
  cmp -s "$OUT/.config" "$verified" && return 0
  echo "error: out/.config no longer matches $verified (what make config verified):" >&2
  diff "$verified" "$OUT/.config" | grep -E '^[<>] (CONFIG_|# CONFIG_)' | head -n 30 >&2
  die "rerun make config with the toolchain you build with (LLVM=$LLVM), then make build"
}
same_as_verified
( cd "$SRC" && make -s "${MAKE_TOOLCHAIN[@]}" O="$OUT" syncconfig ) \
  || die "Kconfig failed with this toolchain (LLVM=$LLVM); out/ was configured for another one. Rerun make config, then make build"
same_as_verified
note "building bzImage with $JOBS jobs$([[ "$LLVM" == 1 ]] && echo ' (LLVM)')"
start=$(date +%s)
( cd "$SRC" && make -s "${MAKE_TOOLCHAIN[@]}" O="$OUT" -j"$JOBS" bzImage )
same_as_verified
cp "$OUT/arch/x86/boot/bzImage" "$OUT/bzImage"
echo "build time: $(( $(date +%s) - start ))s"
ls -l "$OUT/bzImage" | awk '{printf "bzImage: %.1f MB\n", $5/1048576}'
# Sanity: the two cuts that matter most, read back from the built kernel's config.
for opt in CONFIG_MODULES CONFIG_IO_URING CONFIG_USER_NS; do
  grep -q "^$opt=y" "$OUT/.config" && die "$opt is on in the built kernel"
done
echo "built: $OUT/bzImage"

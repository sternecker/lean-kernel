#!/usr/bin/env bash
# Bootable ISO for the VMware/q35 profile (VMWARE=1): $OUT/lean.iso = GRUB + out/bzImage + the initramfs.
# GRUB loads the kernel and the initramfs from the ISO into RAM, the kernel never reads the CD (it has no
# storage driver), and the console is serial. Boots on VMware Workstation/ESXi and QEMU/KVM (pc, q35).
#   BIOS+UEFI hybrid when GRUB's i386-pc modules are installed (Debian: grub-pc-bin); UEFI-only without them.
#   Needs grub-mkrescue (grub2-mkrescue on RHEL), xorriso and mtools (Debian: grub-common xorriso mtools grub-efi-amd64-bin [grub-pc-bin]).
# Stages into a fresh work/iso-stage.XXXXXX and deletes nothing; make clean removes work/.
source "$(dirname "$0")/_env.sh"

[[ "$VMWARE" == "1" ]] || die "the ISO needs the VMware profile's kernel: run with VMWARE=1 (and LEAN_OUT=<dir> to keep it apart from out/)"
for f in bzImage initramfs.cpio.gz; do
  [[ -f "$OUT/$f" ]] || die "no $OUT/$f; run VMWARE=1 make build and scripts/mkinitramfs.sh"
done
# VMWARE=1 only says which profile was asked for, not what $OUT holds: with the default LEAN_OUT, out/ has the
# Firecracker kernel (no PCI, ACPI, EFI or initrd), which would make an ISO that panics or hangs at boot.
# make config saves the config it verified as $PROFILE-<version>.config and make build checks .config still
# matches it, so a match here means this $OUT was configured and built as $PROFILE.
verified="$OUT/$PROFILE-$KERNEL_VERSION.config"
[[ -f "$verified" && -f "$OUT/.config" ]] && cmp -s "$OUT/.config" "$verified" \
  || die "$OUT does not hold a $PROFILE build (no $verified matching $OUT/.config); rerun make config build with VMWARE=1 (and VMCI=1 if wanted) and LEAN_OUT=$OUT"
# The RHEL family names it grub2-mkrescue.
mkrescue="$(command -v grub-mkrescue || command -v grub2-mkrescue)" \
  || die "grub-mkrescue not installed ($PKG_INSTALL $(pkg 'grub-common xorriso mtools' 'grub2-tools-extra xorriso mtools'))"
for t in xorriso mformat; do
  command -v "$t" >/dev/null || die "$t not installed ($PKG_INSTALL $(pkg 'xorriso mtools' 'xorriso mtools'))"
done
grub_lib=/usr/lib/grub   # GRUB's platform modules, on Debian and RHEL alike
mode=hybrid; grub_args=()
if [[ ! -d "$grub_lib/i386-pc" ]]; then
  [[ -d "$grub_lib/x86_64-efi" ]] || die "no GRUB platform modules under $grub_lib ($PKG_INSTALL $(pkg grub-efi-amd64-bin grub2-efi-x64-modules))"
  mode=uefi-only; grub_args=(-d "$grub_lib/x86_64-efi")
  note "no $grub_lib/i386-pc ($PKG_INSTALL $(pkg grub-pc-bin grub2-pc-modules)): building a UEFI-only ISO"
fi

# Kernel command line: the Firecracker one (vm/vm.json.in) without what is specific to it: the root device,
# init=, pci=off, reboot=k. The root is the initramfs, the console is serial, and reboot goes through ACPI.
# panic=1 stays: a panicked guest reboots after a second instead of sitting halted.
base="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boot-source"]["boot_args"])' "$ROOT/vm/vm.json.in")"
args="console=ttyS0,115200 rdinit=/init reboot=acpi"
for a in $base; do
  case "$a" in console=*|reboot=*|pci=off|root=*|rw|init=*) ;; *) args+=" $a" ;; esac
done

mkdir -p "$WORK" "$OUT"
stage="$(mktemp -d "$WORK/iso-stage.XXXXXX")"
mkdir -p "$stage/boot/grub"
cp "$OUT/bzImage" "$stage/boot/bzImage"
cp "$OUT/initramfs.cpio.gz" "$stage/boot/initramfs.cpio.gz"
cat > "$stage/boot/grub/grub.cfg" <<EOF
# lean-kernel ISO. Serial console first (VMware needs a serial port added to the VM to show it); GRUB's own
# screen also stays on the VM display.
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console
set timeout=3
set default=0
menuentry "lean-kernel $KERNEL_VERSION" {
  linux /boot/bzImage $args
  initrd /boot/initramfs.cpio.gz
}
EOF

iso="$OUT/lean.iso"
# The log goes next to the stage, not in it: everything in $stage is packed into the ISO, and this log names
# the build host's paths.
mklog="$stage.mkrescue.log"
"$mkrescue" "${grub_args[@]}" -o "$iso" "$stage" -- -volid LEAN_KERNEL >/dev/null 2>"$mklog" \
  || { cat "$mklog" >&2; die "$(basename "$mkrescue") failed"; }
ls -l "$iso" | awk -v m="$mode" '{printf "iso: %s (%.1f MB, %s)\n", $9, $5/1048576, m}'
echo "kernel args: $args"

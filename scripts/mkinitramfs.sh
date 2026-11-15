#!/usr/bin/env bash
# Busybox initramfs for the VMware/q35 profile (VMWARE=1): $OUT/initramfs.cpio.gz. The kernel in that
# profile has no storage driver, so the whole root filesystem is this archive, unpacked into RAM by the
# kernel and run as /init (PID 1). Same busybox and applets as mkrootfs.sh; built without root privileges
# (fakeroot + cpio, so every file is owned by uid 0). ISO packaging loads it next to the kernel (GRUB initrd).
# Replace with the agent's own tree once the boot path is settled.
# Each run stages into a fresh work/initramfs-stage.XXXXXX and deletes nothing; make clean removes work/.
source "$(dirname "$0")/_env.sh"

# The archive itself doesn't depend on the kernel, but it lands in $OUT next to one, where mkiso.sh packs both:
# keep it out of the Firecracker profile's out/.
[[ "$VMWARE" == "1" ]] || die "the initramfs is for the VMware profile: run with VMWARE=1 (and LEAN_OUT=<dir>, e.g. out-vmware)"

bb="$(command -v busybox)" || die "busybox not installed ($PKG_INSTALL $(pkg busybox-static busybox))"
command -v cpio >/dev/null || die "cpio not installed ($PKG_INSTALL cpio)"
command -v fakeroot >/dev/null || die "fakeroot not installed ($PKG_INSTALL fakeroot)"
mkdir -p "$WORK" "$OUT"
stage="$(mktemp -d "$WORK/initramfs-stage.XXXXXX")"
mkdir -p "$stage"/{bin,sbin,etc,proc,sys,dev,tmp,root,lib,lib64,usr/bin}

cp "$bb" "$stage/bin/busybox"
if ldd "$bb" >/dev/null 2>&1; then
  ldd "$bb" | awk '/=> \//{print $3} /^\s*\/(lib|lib64)/{print $1}' | while read -r lib; do
    mkdir -p "$stage$(dirname "$lib")"; cp -L "$lib" "$stage$lib"
  done
fi
for a in sh mount umount ls cat echo ip ifconfig poweroff reboot ps dmesg uname cut grep head tail sleep hostname setsid unshare true basename tr; do
  ln -sf busybox "$stage/bin/$a"
done

cat > "$stage/init" <<'INIT'
#!/bin/sh
# PID 1 of a RAM-only root. No root= device, no switch_root: this tree is the root for the whole boot.
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
hostname lean
echo
echo "lean-kernel guest (initramfs): $(uname -r)"
echo "root fs:  $(grep ' / ' /proc/mounts | cut -d' ' -f3)"
echo "block devices: $(ls /sys/block 2>/dev/null | tr '\n' ' ')"
echo "io_uring: $( [ -e /proc/sys/kernel/io_uring_disabled ] && echo present || echo absent )"
echo "user ns:  $( unshare -U true 2>/dev/null && echo present || echo absent )"
echo "kallsyms: $( [ -e /proc/kallsyms ] && echo present || echo absent )"
echo "nics:     $(ls /sys/class/net | tr '\n' ' ')"
echo "type 'reboot -f' to exit"
exec setsid sh -c 'exec sh </dev/ttyS0 >/dev/ttyS0 2>&1'
INIT
chmod +x "$stage/init"
echo "lean" > "$stage/etc/hostname"

img="$OUT/initramfs.cpio.gz"
# The chown/-R 0:0 keep root ownership; nothing is writable by anyone but root except /tmp.
fakeroot -- sh -c "chown -R 0:0 '$stage' && chmod -R go-w '$stage' && chmod 1777 '$stage/tmp' && cd '$stage' && find . | sort | cpio -o -H newc -R 0:0 --quiet | gzip -9n > '$img'"
ls -l "$img" | awk '{printf "initramfs: %s (%.1f MB)\n", $9, $5/1048576}'

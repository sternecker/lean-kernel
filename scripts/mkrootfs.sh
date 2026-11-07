#!/usr/bin/env bash
# Minimal ext4 root image from the host's busybox, built without root privileges (fakeroot + mkfs.ext4 -d).
# Enough to prove the kernel boots and to run a shell on the serial console. Replace with a real
# rootfs (debootstrap trixie minbase, or the agent's own image) once the kernel is settled.
# PROBE=<static binary> builds the test image instead (out/rootfs-test.ext4): init runs the probe,
# then runs it again under JAIL_EXEC=<static jail-exec> as uid 65534, prints PROBE-EXIT=<code> and
# PROBE-JAILED-EXIT=<code> on the console, and reboots. scripts/test.sh drives this.
source "$(dirname "$0")/_env.sh"

size_mb="${ROOTFS_MB:-64}"
bb="$(command -v busybox)" || die "busybox not installed ($PKG_INSTALL $(pkg busybox-static busybox))"
stage="$WORK/rootfs-stage"
rm -rf "$stage"; mkdir -p "$stage"/{bin,sbin,etc,proc,sys,dev,tmp,root,lib,lib64,usr/bin}

cp "$bb" "$stage/bin/busybox"
# Copy shared libraries if busybox is dynamically linked (Debian's busybox package is).
if ldd "$bb" >/dev/null 2>&1; then
  ldd "$bb" | awk '/=> \//{print $3} /^\s*\/(lib|lib64)/{print $1}' | while read -r lib; do
    mkdir -p "$stage$(dirname "$lib")"; cp -L "$lib" "$stage$lib"
  done
fi
for a in sh mount umount ls cat echo ip ifconfig poweroff reboot ps dmesg uname cut grep head tail sleep hostname setsid unshare true; do
  ln -sf busybox "$stage/bin/$a"
done

cat > "$stage/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
hostname lean
echo
echo "lean-kernel guest: $(uname -r)"
echo "modules dir present? $( [ -d /lib/modules ] && echo yes || echo no )"
echo "io_uring: $( [ -e /proc/sys/kernel/io_uring_disabled ] && echo present || echo absent )"
# /proc/sys/user/max_user_namespaces exists even with USER_NS=n; actually try to create one.
echo "user ns:  $( unshare -U true 2>/dev/null && echo present || echo absent )"
echo "kallsyms: $( [ -e /proc/kallsyms ] && echo present || echo absent )"
echo "sysrq:    $( [ -e /proc/sysrq-trigger ] && echo present || echo absent )"
echo "retbleed: $(cat /sys/devices/system/cpu/vulnerabilities/retbleed 2>/dev/null || echo unknown)"
echo "bhi:      $(grep -o 'BHI: [^;]*' /sys/devices/system/cpu/vulnerabilities/spectre_v2 2>/dev/null || echo unknown)"
echo "type 'reboot -f' to exit (poweroff -f only halts)"
exec setsid sh -c 'exec sh </dev/ttyS0 >/dev/ttyS0 2>&1'
EOF
if [[ -n "${PROBE:-}" ]]; then
  cp "$PROBE" "$stage/bin/probe"
  cp "$JAIL_EXEC" "$stage/bin/jail-exec"
  cat > "$stage/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmp /tmp
# Keep kernel log lines (expected traps from the probe) off the console the result is parsed from.
echo 1 > /proc/sys/kernel/printk
/bin/probe
echo "PROBE-EXIT=$?"
# The agent's policy shape; fd 3 is open so the probe can check jail-exec closes it.
/bin/jail-exec --rw /tmp --connect 8080 65534 /bin/probe --jailed 3</etc/hostname
echo "PROBE-JAILED-EXIT=$?"
reboot -f
EOF
fi
chmod +x "$stage/init"
echo "lean" > "$stage/etc/hostname"

mkdir -p "$OUT"
img="$OUT/rootfs.ext4"
[[ -n "${PROBE:-}" ]] && img="$OUT/rootfs-test.ext4"
rm -f "$img"
# mkfs.ext4 -d copies the staging files' owners. Without fakeroot every file would belong to the
# build user, and a guest process running as that uid could rewrite /init or busybox on the rw root.
fakeroot -- sh -c "chown -R 0:0 '$stage' && chmod -R go-w '$stage' && chmod 1777 '$stage/tmp' && /sbin/mkfs.ext4 -q -L lean -d '$stage' '$img' ${size_mb}M"
echo "rootfs: $img (${size_mb} MB)"

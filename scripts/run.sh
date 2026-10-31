#!/usr/bin/env bash
# Boot out/bzImage + out/rootfs.ext4 in Firecracker with the serial console on this terminal.
# NET=1 attaches tap0 (create it first with scripts/net-tap.sh). Exits when the guest powers off.
source "$(dirname "$0")/_env.sh"

[[ -x "$FC" ]] || die "firecracker missing; run make deps"
[[ -f "$OUT/bzImage" ]] || die "no out/bzImage; run make build"
[[ -f "$OUT/rootfs.ext4" ]] || die "no out/rootfs.ext4; run make rootfs"

cfg="$ROOT/vm/vm.json"
sed -e "s|@KERNEL@|$OUT/bzImage|" -e "s|@ROOTFS@|$OUT/rootfs.ext4|" -e "s|@VSOCK@|$ROOT/vsock.sock|" \
    "$ROOT/vm/vm.json.in" > "$cfg"
if [[ "${NET:-0}" == "1" ]]; then
  grep -q "^# CONFIG_VIRTIO_NET is not set" "$OUT/.config" 2>/dev/null \
    && die "NET=1 but out/.config is the vsock-only profile (no NIC driver); rebuild without VSOCK_ONLY=1"
  python3 - "$cfg" <<'EOF'
import json,sys
p=sys.argv[1]; c=json.load(open(p))
c["network-interfaces"]=[{"iface_id":"eth0","guest_mac":"06:00:AC:10:00:02","host_dev_name":"tap0"}]
json.dump(c,open(p,"w"),indent=2)
EOF
fi
rm -f "$ROOT/firecracker.sock" "$ROOT/vsock.sock"
note "booting (vcpus/mem from vm/vm.json.in); 'reboot -f' in the guest to exit"
exec "$FC" --no-api --config-file "$cfg"

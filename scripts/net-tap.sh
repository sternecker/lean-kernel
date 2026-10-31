#!/usr/bin/env bash
# Optional: host-side tap for guest networking. Needs sudo. Deliberately NOT masqueraded to the
# internet: the guest should only reach an egress proxy, which is the whole point of the design.
# Usage: sudo scripts/net-tap.sh up|down
set -euo pipefail
tap=tap0; host_ip=172.16.0.1/24; owner="${SUDO_USER:-$USER}"
case "${1:-}" in
  up)
    ip tuntap add dev "$tap" mode tap user "$owner"
    ip addr add "$host_ip" dev "$tap"
    ip link set "$tap" up
    echo "$tap up at $host_ip; guest: ip addr add 172.16.0.2/24 dev eth0 && ip link set eth0 up"
    ;;
  down) ip link del "$tap" ;;
  *) echo "usage: sudo $0 up|down"; exit 2 ;;
esac

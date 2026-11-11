# lean-kernel as a bootable ISO (VMware, QEMU/KVM)

This branch builds a second kernel profile and packs it into a bootable ISO that runs on VMware (Workstation, Fusion on x86, ESXi) and on QEMU/KVM with the `pc` or `q35` machine. The Firecracker profile on `main` is unchanged: its config is byte-identical to before.

The ISO is a **headless, network-less box with a serial console**. That is deliberate. It is the smallest guest that proves the kernel boots on a PCI/ACPI hypervisor, and every driver it does not have is attack surface it does not carry.

## Why a second profile

The Firecracker kernel has `CONFIG_PCI` and `CONFIG_ACPI` off and finds its devices over virtio-mmio. VMware and the `pc`/`q35` machines present PCI and ACPI hardware instead, so that kernel would see nothing there. `configs/vmware.fragment` is applied on top of `lean.fragment` and `llvm.fragment` with `VMWARE=1`.

| | Firecracker (default) | `VMWARE=1` |
|---|---|---|
| Bus / firmware | virtio-mmio, no PCI, no ACPI | PCI + MSI + ACPI, EFI stub |
| Root | ext4 on virtio-blk | initramfs in RAM, unpacked from the ISO by GRUB |
| Storage drivers | virtio-blk, ext4 | **none**: no SCSI, ATA, NVMe, ISO9660 |
| Console | serial | serial only |
| Network | virtio-net + TCP/IP | **none**: no NIC driver, no TCP/IP, no `AF_PACKET` |
| vsock | virtio-vsock | virtio-vsock (KVM only; VMware has none, and VMCI is left out) |
| Enabled options (`=y`/`=m`) | 978 | 1010 |
| Hardening checker | 15 accepted FAILs | 18 accepted FAILs |

Choices and their costs:

- **No storage drivers.** GRUB reads the ISO through the firmware and loads the kernel and the initramfs into RAM, so the kernel never touches the CD. A disk driver is a larger attack surface than most devices, and a guest with no disk has nothing persistent to tamper with. The cost is that the whole root lives in RAM.
- **Serial console only.** A VGA text console needs `CONFIG_VT`, which selects the whole `INPUT` subsystem that `lean.fragment` cuts. See "Running it in VMware" for what that means in practice.
- **No ACPI power button.** The `ACPI_BUTTON`, `ACPI_PROCESSOR`, `ACPI_THERMAL` and `ACPI_VIDEO` drivers are off because they force `INPUT` and `THERMAL` back on. The hypervisor's "Shut Down Guest" does nothing; use "Power Off", or `poweroff -f` inside. Reboot works (`reboot=acpi`).
- **No network at all.** A NIC driver parses whatever a virtual device hands it, and the TCP/IP stack parses whatever arrives. The VM can still have a virtual NIC attached in its settings; the guest has no driver for it and ignores it. To add one later: `CONFIG_VMXNET3=y` in the fragment and drop the `VIRTIO_NET`, `INET` and `PACKET` cuts.
- **`VMWARE=1` and `VSOCK_ONLY=1` are refused together.** The VMware profile already contains everything the vsock-only profile cuts.
- **Extra cuts** that PCI/ACPI/EFI switch on by default: PCI hotplug and ASPM, the EFI variable filesystem and pstore, legacy virtio-pci, PCI serial-card variants, Intel perf uncore/RAPL/cstate, vendor RNG drivers.

## Building

Host packages (Debian; RHEL names differ, the scripts print them): `grub-common xorriso mtools grub-efi-amd64-bin grub-pc-bin cpio fakeroot busybox`. Without `grub-pc-bin` the ISO is built UEFI-only, and the script says so.

```
make fetch                                         # as in HOWTO.md, once
export VMWARE=1 LEAN_OUT=$PWD/out-vmware           # keep this profile apart from out/
scripts/configure.sh                               # base + lean + llvm + vmware fragments; proves every line stuck
scripts/build.sh                                   # -> out-vmware/bzImage (about 2-4 minutes, 4.6 MB)
scripts/check.sh                                   # kernel-hardening-checker; fails on any unaccepted FAIL
scripts/mkinitramfs.sh                             # -> out-vmware/initramfs.cpio.gz (1.5 MB, root-owned, no sudo)
scripts/mkiso.sh                                   # -> out-vmware/lean.iso (27 MB hybrid, 20 MB UEFI-only)
```

Both scripts stage in a fresh `work/*-stage.XXXXXX` directory and delete nothing, so old stage directories accumulate in `work/` until `make clean`.

The kernel command line in `grub.cfg` is taken from `vm/vm.json.in` at build time, minus the Firecracker-only parts (`root=`, `init=`, `pci=off`, `reboot=k`), plus `console=ttyS0,115200 rdinit=/init reboot=acpi`. It keeps `lockdown=confidentiality` and the sysctls.

## Running it in QEMU

```
# BIOS
qemu-system-x86_64 -M q35 -accel kvm -cpu host -m 512 -nodefaults -nographic -serial stdio -no-reboot \
    -cdrom out-vmware/lean.iso
# UEFI
qemu-system-x86_64 -M q35 -accel kvm -cpu host -m 512 -nodefaults -nographic -serial stdio -no-reboot \
    -bios /usr/share/ovmf/OVMF.fd -cdrom out-vmware/lean.iso
```

`-M pc` works as well. GRUB shows a 3 second menu on the serial console, then the guest prints a banner and gives a busybox shell. `reboot -f` exits QEMU.

## Running it in VMware

1. Create a VM: guest OS "Other Linux 6.x kernel 64-bit", 512 MB or more, **no hard disk needed**. Attach `lean.iso` as the CD/DVD drive, connected at power on.
2. **Add a serial port**: VM settings, Add, Serial Port, output to a file or a named pipe. This is required. VMware has no serial port by default, and the guest has no VGA console, so without one you see GRUB's menu on the VM display and then a blank screen.
3. Firmware: BIOS or UEFI, either works. With UEFI, Secure Boot must be off (the kernel and GRUB are not signed).
4. Power on, then read the serial output (tail the file, or connect to the pipe).

## What was tested

On Debian 13, kernel 6.18.62, QEMU with KVM:

| Check | Result |
|---|---|
| `configure.sh` | pass: 0 fragment lines failed |
| `check.sh` (checker) | pass: 18 FAILs, all accepted for the `vmware` scope |
| Default (Firecracker) config | unchanged: byte-identical; its checker still passes with 15 accepted |
| Kernel + initramfs, `-M q35`, no disk, a vmxnet3 attached | pass: `/sys/block` empty, only `lo` in `/sys/class/net`, no TCP/UDP in `/proc/net` |
| ISO, BIOS (SeaBIOS), `q35` and `pc` | pass: GRUB menu, kernel, shell, clean ACPI reboot |
| ISO, UEFI (OVMF), `q35` | pass: same |

**Not tested:**

- **Real VMware**, on any of Workstation, Fusion or ESXi. QEMU's SeaBIOS and OVMF are close to VMware's firmware but not identical.
- **Secure Boot.**
- **Non-QEMU hypervisors** (Hyper-V, VirtualBox).
- **vsock on KVM.** `VIRTIO_VSOCKETS` is in the kernel, but no vsock device was attached.

## Limits

- **No persistence and no network.** The guest is for demonstration and kernel testing. It is not the agent image: `run-agent.sh`, `api-proxy.py` and the jailer assume Firecracker's vsock and its NIC-less design, and nothing here replaces them. The shipped root is plain busybox.
- **UEFI has no display.** There is no framebuffer console either, so serial is the only console under UEFI too.
- **The root is a RAM filesystem.** There is no `switch_root` and no disk to fall back to. Memory needs to hold the initramfs (1.5 MB here) plus whatever the guest runs.
- **Two EFI checker FAILs are accepted** (`EFI_DISABLE_PCI_DMA`, `RESET_ATTACK_MITIGATION`). Both defend against physical-hardware attacks, and in a VM the PCI bus and firmware are the hypervisor's. `EFI_DISABLE_PCI_DMA` is also known to break some firmware, so enabling it would need testing on real VMware.

## Next steps

1. Boot it on real VMware, BIOS and UEFI, and record what differs.
2. Decide whether a network profile is wanted (re-add `VMXNET3`, with `INET` on or a vsock-only variant on KVM), and what bringing the NIC up would involve.
3. Replace the busybox initramfs with the agent's own tree, if the ISO is to run it.
4. Add `make iso`-style targets for the three scripts, and put `cpio`, `fakeroot`, `grub-*` and `xorriso` in `deps-check.sh`.

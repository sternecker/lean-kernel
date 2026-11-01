# HOWTO: from clone to a booted guest

Host: Debian 13 (trixie), x86_64, KVM. Everything runs as your user except the one `apt install`
and the optional tap device. Commands assume you are in the repo root.

## 0. Where things stand (2026-10-23)

Already done and committed:
- Firecracker v1.17.0 fetched and sha256-verified into `bin/` (`make deps` re-does this on a fresh clone).
- `linux-6.18.58` (current 6.18 longterm) fetched, verified against kernel.org's `sha256sums.asc`, extracted to `work/`.
- `/dev/kvm` present and writable by this user.

Blocked at `make config`: the kernel's Kconfig tooling needs `flex` and `bison`; the build needs `libelf-dev` and `libssl-dev`.

## 1. Install the build packages (once, sudo)

```sh
sudo apt install flex bison libelf-dev libssl-dev
sudo apt install clang-22 lld-22      # the default clang build; both are in trixie main
```

Use the versioned packages: plain `clang lld` installs 19, which can't build `KSTACK_ERASE`.
`LLVM=0` builds with gcc and needs only the first line, but loses CFI, RANDSTRUCT and KSTACK_ERASE.

`make deps` tells you what's still missing and prints the apt line.

## 2. Configure

```sh
make config            # clang build (default): also applies configs/llvm.fragment
LLVM=0 make config     # gcc build: no CFI, RANDSTRUCT or KSTACK_ERASE
VSOCK_ONLY=1 make config   # vsock-only profile: also applies configs/vsock-only.fragment
```

What happens: `base-firecracker-x86_64-6.18.config` + `configs/lean.fragment` are merged with the kernel's
`merge_config.sh`, then `make olddefconfig` resolves dependencies. Then `scripts/configure.sh` re-reads
every fragment line against the final `out/.config`.

Expected output ends with something like:

```
enabled options: base 1391 -> lean <smaller number>
verification: 0 failed, N warnings
config: <repo>/out/.config
```

- `warn ... not present in final config`: the option name doesn't exist in 6.18 (renamed or removed),
  or a dependency is off so Kconfig hides it. With `VSOCK_ONLY=1`, expect this for `CIFS`, `NFS_FS`,
  `NFSD` and `SMB_SERVER`, which depend on `INET`. Harmless for an `is not set` line; look it up in `work/linux-6.18.58/` with
  `grep -rn "config NAME" --include=Kconfig*` and fix the fragment so the warning goes away.
- `FAIL ... wanted off, final config has =y`: a dependency turned the option back on. Find what selects it
  (`make O=out menuconfig`, then `/` search, shows "Selected by"). Either cut the selector too or
  record in the fragment why this one stays. Do not use `ALLOW_DRIFT=1` except to look at the result.
- `FAIL ... wanted y, final config has <absent>`: a dependency of a hardening option is off. Same drill.

First run on a new kernel series usually produces 3 to 10 of these. That's the work; it's finite.

## 3. Build

```sh
make build             # clang by default; LLVM=0 make build for gcc
```

Builds `out/bzImage`, which `make run` boots. Use bzImage, not the bare `vmlinux` ELF: only the bzImage
decompressor randomizes the kernel base (KASLR). `out/vmlinux` and `out/System.map` stay for decoding oopses.
With 12 threads a config this size builds in a few minutes. Prints build time and size; expect about 5 to 6 MB.
The script refuses to finish if `CONFIG_MODULES`, `CONFIG_IO_URING` or `CONFIG_USER_NS` ended up on.

## 4. Grade it

```sh
make check
```

Clones `kernel-hardening-checker` into `work/` and runs it against `out/.config`, failures only.
Some FAILs are intentional for a microVM guest (no modules means module-signing checks fail; no ACPI,
no PCI). Read each one. For accepted ones, add a line under "Accepted checker failures" at the bottom
of this file so the next run isn't a mystery.

## 5. Root filesystem

```sh
make rootfs            # ROOTFS_MB=128 make rootfs for a bigger image
```

Builds `out/rootfs.ext4` (64 MB) from the host's `busybox` plus its shared libraries, no root needed
(`mkfs.ext4 -d`). `/init` mounts proc/sys/dev and gives you a shell on the serial console.
This rootfs exists to prove the kernel; the agent's real image replaces it later.

## 6. Boot

```sh
make run
```

Firecracker starts with `vm/vm.json` (2 vCPUs, 512 MB, vsock CID 3, no network), console on your
terminal. The init script prints the first test:

```
lean-kernel guest: 6.18.58
modules dir present? no
io_uring: absent
user ns:  absent
kallsyms: absent
sysrq:    absent
retbleed: Mitigation: IBRS
bhi:      BHI: SW loop, KVM: SW loop
```

`absent` means the code is really gone, not just disabled by sysctl. `make test` (§6a) checks far more.
Leave with `reboot -f` (`poweroff -f` halts the guest but leaves Firecracker running). If the guest panics on boot, the serial log is on your terminal; the usual
causes are a missing virtio or ext4 option (both pinned `=y` in the fragment, so check `make config`
didn't FAIL on them) or a boot arg the lean kernel doesn't understand.

Useful in-guest checks:

```sh
cat /proc/cmdline                       # confirm lockdown=confidentiality took
cat /sys/kernel/security/lockdown       # [confidentiality] when LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
ls /proc/sys/kernel | grep -c .         # small
dmesg | grep -i -E "landlock|seccomp|yama|lockdown"
```

## 6a. Probe the walls

```sh
make test
```

Builds `tests/probe.c` and `guest/jail-exec.c` statically, puts them in a separate image
(`out/rootfs-test.ext4`) whose init runs the probe and reboots, boots that headless with the same kernel
command line as `make run`, and fails unless every check passes. Takes about 10 seconds after the build.
Full console log: `out/test.log`. Expect `PROBE: root 84 / user 72 / jailed 25 passed, 0 failed`. The root pass includes the image-ownership checks, `jail-exec` bad-UID refusals, and the boot sysctls (`kptr_restrict=2`, `memfd_noexec=2`, executable memfd refused). The jailed pass runs with the agent's policy shape (`--rw /tmp --connect 8080`). It checks the Landlock file and TCP rules against a world-writable directory, which only Landlock can refuse. It also checks that vsock and netlink sockets and an unlisted syscall are refused, and that inherited fds are closed.

The probe runs three passes: as root, as uid 65534, and as uid 65534 under `jail-exec` (§6c).
Cut code must be gone even for root:
- Cut syscalls return `ENOSYS`: io_uring, bpf, userfaultfd, kcmp, AIO, rseq, kexec, module loading,
  modify_ldt, iopl/ioperm, uselib, sysfs, SysV IPC (msg/sem/shm), POSIX mqueues, keyrings
  (add_key/keyctl/request_key), NUMA (mbind/set_mempolicy/migrate_pages/move_pages),
  quotas (quotactl/quotactl_fd), swap (swapon/swapoff), process accounting (acct).
  `unshare(CLONE_NEWUSER)` returns `EINVAL`.
- Cut sockets fail: AF_PACKET, AF_INET6, netlink XFRM and NETFILTER, MPTCP.
- Cut device and proc files don't exist: `/dev/mem`, `/dev/port`, `/dev/fuse`, `/dev/net/tun`, loop,
  MSR/CPUID, `/proc/kcore`, `/proc/kallsyms`, sysrq, pagemap, core_pattern, debugfs, tracefs.
- 32-bit `int 0x80` and a vsyscall-page read kill the process. `/proc/self/mem` can't write to read-only text.
- As the user only: no mapping below 64 KiB, no dmesg, no ptrace of a same-uid sibling (Yama), and
  `EPERM` from the root-only calls the kernel still has: mount, fsopen, chroot, `unshare(CLONE_NEWNS)`,
  open_by_handle_at, settimeofday, reboot, ptrace of PID 1. **Run the agent as non-root:**
  as root in the guest, every one of those works.

Positive checks make sure the test can't pass on a broken guest: vsock and Unix sockets work,
Landlock reports an ABI, seccomp strict mode really kills, and lockdown reads `[confidentiality]`.

`INFO` and `SURFACE` lines are reported but don't fail the run. They are what the plain user can still
reach without `jail-exec`:
- `perf_event_open`: x86 forces `PERF_EVENTS` on, and upstream's strictest `perf_event_paranoid` (2)
  still allows self-profiling. `jail-exec` blocks it.
- `vmsplice`, `process_vm_readv`, `name_to_handle_at`: blocked by `jail-exec`.
- `setxattr` (user.*), `memfd_create`, `memfd_secret`: allowed. Runtimes use them; revisit with an
  allowlist once the agent's syscall set is known.
- `AF_INET` is available in the default profile and unavailable with `VSOCK_ONLY=1`.

Run it after every `make build`. A new FAIL means a cut stopped holding: read the line, then check
`make config` output for the option behind it. A new kernel version can rename a symbol (see the
`BLK_DEV_BSG` miss in git history), and `make config` only warns when an off line names a missing symbol.

## 6b. List the kernel's syscalls

```sh
make syscalls
```

Reads `sys_call_table` out of `out/vmlinux` (no boot) and prints how many syscalls are present and which
are compiled out; the full list goes to `out/syscalls.txt`. As of 2026-10-31: 311 present, 72 compiled out
of 383. Blind spot: `iopl`/`ioperm` are compiled in but return `ENOSYS` (`X86_IOPL_IOPERM=n`), so they
count as present here; `make test` checks what actually happens.

## 6c. Start the agent through jail-exec

```sh
# in the guest, as root, e.g. from /init
jail-exec [--rw PATH]... [--connect PORT]... [--bind PORT]... [--vsock] UID COMMAND [ARGS...]
jail-exec --rw /home/agent --rw /tmp --connect 8080 10000 /bin/bash     # what the agent VM runs
```

`guest/jail-exec.c` (static, no libseccomp) applies these in order and fails closed (exit 127) at any step:

1. **Privilege drop.** It drops to `UID`, which must be 1 to 65534 written as plain digits. It then checks
   that every id changed and that root can't be regained.
2. **`no_new_privs`.**
3. **Landlock (ABI 6 or later).**
   - Everything is read and execute only, except `/dev`, which also allows writes and device ioctls (terminals, `/dev/null`).
   - Each `--rw` path gets full access beneath it.
   - The only TCP connects and binds allowed are to the `--connect` and `--bind` ports.
   - Scoping stops the agent from signalling, or reaching abstract unix sockets of, processes outside its own domain (init, socat).
   - With ABI 7, denials after exec go to the kernel log (`type=1423`).
4. **File descriptors.** Every inherited fd above 2 is closed.
5. **seccomp allowlist.** The checks run in this order:
   - A non-x86_64 or x32 syscall kills the process.
   - An explicit denylist returns `EPERM`: `perf_event_open`, `vmsplice`, ptrace, process_vm_*, `pidfd_getfd`,
     `process_madvise`, `kcmp`, file handles, fanotify, `unshare`/`setns`, the mount family, swap, reboot,
     clock setting including `adjtimex`, hostname, quota and syslog.
   - `clone` with namespace flags returns `EPERM`. `clone3` returns `ENOSYS`, because its flags sit behind a
     pointer seccomp can't read, and glibc falls back to `clone`.
   - `socket()` works only for `AF_UNIX`, `AF_INET` and `AF_INET6`, plus `AF_VSOCK` with `--vsock`.
   - Then comes the allowlist. Anything not on it returns `ENOSYS`.

   Every refusal is logged (`type=1326`, `syscall=N`).

The allowlist is the set of syscalls Claude Code, bash, busybox and socat were seen to make, plus close relatives
of those calls. To redo it after a Claude Code update, or for a different agent:

```sh
STRACE=1 make agent-rootfs && AGENT_STRACE=1 TASK='...' make agent   # out/strace-agent.txt, out/strace-socat.txt
make agent-rootfs                                                    # rebuild without strace afterwards
```

`make agent` prints what the jail refused after each headless run. Expect one `syscall=435` (`clone3`, by design)
and one `syscall=41` (a `socket()` call from Claude Code, almost certainly netlink, which it doesn't need).

## 7. Networking (optional, sudo)

```sh
sudo scripts/net-tap.sh up      # creates tap0 at 172.16.0.1/24, owned by you
NET=1 make run
# in the guest:
ip addr add 172.16.0.2/24 dev eth0 && ip link set eth0 up
ping -c1 172.16.0.1
```

Not available with the vsock-only profile (`VSOCK_ONLY=1`): it has no NIC driver, and `run.sh` refuses
`NET=1` against it.

The tap is deliberately not masqueraded. In the real design the guest's only route is to the egress
proxy (Envoy) on the host side, and the proxy owns DNS. Don't add a NAT rule "just to test"; that is
the exact hole the architecture exists to close.

## 8. Cadence (weekly, 30 seconds)

```sh
scripts/fetch-kernel.sh --check
```

Prints `up to date` or `BEHIND: pinned X, current longterm Y`. When behind:

1. Edit `VERSION`: `KERNEL_VERSION=<new>`.
2. `rm -f out/scripts/basic/randstruct.seed` so the new kernel gets a fresh RANDSTRUCT layout (the
   seed otherwise survives every rebuild; see NOTES §5). Then `make fetch config build check` and
   reboot-test with `make run`.
3. Commit `VERSION` and the `.config` diff (`out/lean-<ver>.config` is copied for exactly this; diff it
   against the previous one before committing).

Firecracker: watch https://github.com/firecracker-microvm/firecracker/releases; bump
`FIRECRACKER_VERSION` and `FIRECRACKER_SHA256` in `VERSION`, then `make deps`.

If the weekly check isn't happening, this guest kernel is worse than a distro kernel, because a distro
kernel patches itself.

## 9. What comes after a clean boot

In order, one at a time:

1. **Real rootfs.** `debootstrap --variant=minbase trixie` (needs sudo) or the agent's container image
   flattened to ext4. Keep it read-only (`is_read_only: true` in `vm/vm.json.in`) and give the agent a
   separate scratch drive.
2. **Jailer.** Run Firecracker under the jailer (chroot, cgroups, its own seccomp on the VMM
   process). The VMM is host-side code the guest talks to; it deserves its own jail. For the agent VM
   this is set up: `sudo scripts/jail-setup.sh`, see 9.5.
   Copy `out/bzImage` into the chroot, not `vmlinux`: KASLR only happens on the bzImage path.
3. **Egress.** vsock from guest to a host-side proxy, or the tap to an Envoy pod with
   default-deny NetworkPolicy. Allowlist by destination first, then per-tool method/path/size via
   ext_authz once TLS termination is in place.
4. **Then** the in-guest stack from the reading: Landlock + seccomp around the agent process. Inside a
   lean guest they are the second wall, not the first.

### 9.5 Claude Code in the VM (first test, before the jailer)

```sh
claude setup-token                       # on the host; prints a long-lived subscription token
mkdir -p ~/.config/lean-kernel && (umask 077; cat > ~/.config/lean-kernel/oauth-token)   # paste it, then ctrl-d
make agent-rootfs                        # out/rootfs-agent.ext4: the host's claude binary + bash + socat + jail-exec
make agent                               # interactive: bash as uid 10000, run `claude`; `exit` powers off
TASK='List the files in / and say what this machine is.' make agent   # headless, log in out/agent.log
```

The path: `claude` in the guest -> `127.0.0.1:8080` -> socat (as nobody, under jail-exec) -> vsock CID 2
port 8080 -> `out/vsock-agent.sock_8080` -> `scripts/api-proxy.py` on the host -> `https://api.anthropic.com`.
The guest holds only a placeholder token. The proxy swaps in the real one, forwards only `POST /v1/messages`
and `/v1/messages/count_tokens`, and logs one line per request to `out/agent-proxy.log`. It also rejects any
request that asks Anthropic's servers to reach out for the agent: server tools (`web_fetch`, `web_search`, code
execution) and `mcp_servers`. Otherwise a URL with data in its query string would be a way out. Claude Code's WebSearch
tool is therefore unavailable in the VM.
Each session (one proxy process) also has a budget: 500 requests, 50M input tokens (cache reads included), 1M output
tokens and 60 requests a minute, with an optional model allowlist. Change them with `AGENT_MAX_REQUESTS`,
`AGENT_MAX_INPUT_TOKENS`, `AGENT_MAX_OUTPUT_TOKENS`, `AGENT_RPM` and `AGENT_MODELS='claude-sonnet-*'` (0 = unlimited).
Each forwarded request's log line shows its tokens and the running total, and the log ends with a session summary.
A Claude Code request costs about 16k input tokens, almost all of it cached system prompt and tool definitions.
Over budget, the agent gets a 403 (which Claude Code labels "Failed to authenticate") and stops. Over the rate,
it gets a 429 and backs off. In the guest, `/proc` is `hidepid=invisible`, so the agent sees only its own
processes, and the agent runs with `umask 077`. The guest has no other
route out. Root is read-only. `/home/agent` is a fresh 512 MB scratch drive each run (`KEEP_SCRATCH=1` keeps it).
`/tmp` and `/home/agent` are mounted `noexec`. With `vm.memfd_noexec=2` and no interpreter in the image that
loads native code, the agent can't run a binary it wrote, which is what most kernel exploits need. `AGENT_EXEC=1 make agent`
lifts this for workloads that build and run code. The protection weakens once the image gains Python, Node or a compiler.
VM memory is 2 GB. This needs the default kernel profile, because `VSOCK_ONLY=1` also removes loopback TCP.

**Jailed (9.2).** Run `sudo scripts/jail-setup.sh` once, and `make agent` uses the jail from then on. `JAIL=0`
runs unjailed and `JAIL=1` refuses to run without the jail. What the setup installs:
- The users `lean-fc` and `lean-proxy`.
- Root-owned copies of the jailer and Firecracker from the pinned release tarball, in `/usr/local/lib/lean-agent`.
  Root never runs the ones in `bin/`, because you can write to that directory.
- The wrapper, `/usr/local/sbin/lean-agent-jail`.
- `/etc/lean-agent.conf`.
- A sudoers rule that lets you run only that wrapper without a password.

Each run gets a fresh chroot under `/srv/lean-agent/firecracker/<id>/root`:
- **Firecracker** runs as `lean-fc` in an empty network namespace, so it has no route anywhere. A cgroup caps it
  at 2.5 GiB of memory, 64 pids and 2 CPUs, and the jailer applies an fd limit and Firecracker's own seccomp filter.
- **The proxy** runs as `lean-proxy`, with no groups, no capabilities and `no_new_privs`. The wrapper pipes the
  token to it, so `lean-proxy` never needs access to your home directory, which is mode 710 anyway.
- **Inputs:** the wrapper reads the kernel, images, config and proxy script as you and copies them into the jail,
  so root never reads a file for it that you couldn't.
- **Cleanup:** the scratch drive is copied back to `out/` for `KEEP_SCRATCH=1`, and everything else is removed.

`sudo lean-agent-jail --check` verifies the installation. After editing `scripts/lean-agent-jail`, run
`sudo scripts/jail-setup.sh` again; `sudo scripts/jail-setup.sh uninstall` removes it all. Changes to the proxy
take effect without reinstalling, because the wrapper copies `scripts/api-proxy.py` into the jail on every run.

Not yet:
- The proxy has full host network access instead of a namespace whose only route is upstream.
- Firecracker isn't in its own PID namespace: `--new-pid-ns` makes the jailer exit early, so the wrapper
  couldn't wait for the VM.
- Claude Code is the host's binary, not a pinned version.

## Troubleshooting

- `make config` fails before verification with a `flex: not found` or `bison` error: step 1.
- `fatal error: gelf.h` or `openssl/bio.h` during build: `libelf-dev` / `libssl-dev`, step 1.
- `pahole` missing: `apt install dwarves` (only needed if `CONFIG_DEBUG_INFO_BTF=y` sneaks in; it shouldn't).
- Firecracker: `Permission denied` on `/dev/kvm`: your user isn't in the `kvm` group (it is, as of 10/23).
- Guest hangs with no output: `console=ttyS0` needs `CONFIG_SERIAL_8250_CONSOLE=y` (pinned) and the
  Firecracker config's `boot_args`; check `vm/vm.json` was regenerated from `vm.json.in`.
- `IBT`/`shadow stack` warnings in dmesg: the host CPU (i9-8950HK) lacks CET. The options are harmless
  there and start working on hardware that has it.

## Accepted checker failures

Recorded 2026-10-31 against 6.18.58. First run (gcc): 50 FAILs. Now clang 22 (default): 15. gcc 14.2 (`LLVM=0`): 20.
clang is the default because it is the safer build: it adds CFI, RANDSTRUCT and KSTACK_ERASE, and it passed
the same boot test (self-test all absent, kCFI active, KASLR offsets differ per boot, clean dmesg).
The build prints 10 modpost `section mismatch` warnings from `__apply_fineibt`, `cfi_enable_callers` and `cfi_rewrite_*` -> `.init.text`; that code only
runs during boot-time alternatives patching (it would also run on module load, but MODULES=n), and boot is clean. Re-check them on each kernel or clang bump.

Not applicable to a no-PCI virtio-mmio guest:
- `X86_MCE`, `X86_MCE_INTEL`, `X86_MCE_AMD`: Firecracker doesn't forward machine checks; the host handles hardware errors.
- `INTEL_IOMMU`, `AMD_IOMMU`, `INTEL_IOMMU_DEFAULT_ON`, `INTEL_IOMMU_SVM`: no IOMMU is exposed to the guest.
- `HW_RANDOM_TPM`: no TPM. Entropy comes from virtio-rng.
- `WERROR`: build-time only. It buys nothing at runtime and could break a build on a newer compiler.

Chosen LSM stack (landlock, lockdown, yama):
- `SECURITY_SELINUX`, `LSM` without selinux: SELinux was cut on purpose (NOTES §3).
- `LSM_MMAP_MIN_ADDR`: only exists with SELinux. `DEFAULT_MMAP_MIN_ADDR=65536` sets the same floor.

Checker naming lag (clang build):
- `CFI_CLANG`, `CFI_PERMISSIVE`: 6.18 renamed the option to `CONFIG_CFI`; `CFI_CLANG` is a hidden
  transitional symbol. `CONFIG_CFI=y` and `CFI_PERMISSIVE` off are verified by `make config`.

Compiler-specific:
- `GCC_PLUGIN_LATENT_ENTROPY`: gcc plugins only; no clang equivalent. Boot entropy comes from
  `random.trust_cpu=on` (RDRAND) and virtio-rng.
- gcc build only: `RANDSTRUCT_FULL`, `KSTACK_ERASE` (+`_METRICS`, `_RUNTIME_DISABLE`), `CFI_*`. These need
  clang (or gcc plugin headers, `gcc-14-plugin-dev`, for the first two). All are on in the default clang build.

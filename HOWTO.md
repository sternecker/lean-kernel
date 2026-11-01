# HOWTO: from clone to a booted guest

Host: Debian 13 (trixie), x86_64, KVM. Everything runs as your user except the one `apt install`
and the optional tap device. Commands assume you are in the repo root.

## 0. Where things stand (2026-11-01)

Working on the development host:
- The kernel (`linux-6.18.58`, pinned and sha256-verified) configures, builds and passes `make check` and
  `make test` in both profiles, the default (`out/`) and vsock-only (`out-vsock/`); `scripts/all.sh --vsock`
  runs every step for both.
- The agent VM (9.5) runs Claude Code jailed: Firecracker under the jailer with a uid per run, the API proxy as
  `lean-proxy`, the credential outside the VM. `make agent-test` passes 31 checks.

On a fresh clone, start at section 1. `make deps` fetches and verifies Firecracker; `make fetch` the kernel.

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
Full console log: `out/test.log`. Expect `PROBE: root 96 / user 83 / jailed 30 passed, 0 failed` (vsock-only: `jailed 28`). Both passes start with checks that `/proc`, `/sys` and `/dev` are actually mounted, so a failed mount can't make the
"absent" checks pass. The vsock-only build gets `probe_profile=vsock` on its kernel command line and asserts that
IPv4 is gone. To test that profile without touching `out/`, run `VSOCK_ONLY=1 LEAN_OUT=$PWD/out-vsock make config build test`.
The root pass includes the image-ownership checks, `jail-exec` bad-UID refusals, and the boot sysctls (`kptr_restrict=2`, `memfd_noexec=2`, executable memfd refused). The jailed pass runs with the agent's policy shape (`--rw /tmp --connect 8080`). It checks the Landlock file and TCP rules against a world-writable directory, which only Landlock can refuse. It also checks that vsock and netlink sockets and an unlisted syscall are refused, and that inherited fds are closed.

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

1. **Privilege drop.** It empties the capability bounding and ambient sets, then drops to `UID`, which must be
   1 to 65534 written as plain digits. It clears every capability set, then checks that every id changed, that
   no capability is left in any set, and that root can't be regained.
2. **`no_new_privs`.**
3. **Landlock (ABI 6 or later).**
   - Everything outside `/dev` is read and execute only.
   - In `/dev` the agent can open only `null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx`, `/dev/pts` and
     the terminal it was started on, with read, write and ioctl. It can't open `kmsg`, `hwrng`, `cpu_dma_latency`,
     the disks or `vsock`. Landlock rules only ever add access, so read access is granted per top-level entry
     instead of on `/`, because a rule on `/` would cover `/dev` too.
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
STRACE=1 make agent-rootfs && AGENT_STRACE=1 TASK='...' make agent   # out/runs/latest/strace-{agent,socat}.txt
make agent-rootfs                                                    # rebuild without strace afterwards
```
(Without the jail installed yet, add `JAIL=0`; see 9.5.)

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

1. Edit `VERSION`: set `KERNEL_VERSION=<new>`, then run `scripts/fetch-kernel.sh --pin` and copy the
   `KERNEL_SHA256=` line it prints into `VERSION`. It reports whether the signature on kernel.org's
   `sha256sums.asc` checked out. That only works if gpg has the kernel.org autosigner key
   (`gpg --locate-keys autosigner@kernel.org`, once). `make fetch` refuses any tarball that doesn't match the pin.
2. `rm -f out/scripts/basic/randstruct.seed` so the new kernel gets a fresh RANDSTRUCT layout (the
   seed otherwise survives every rebuild; see NOTES §5). Then `make fetch config build check` and
   reboot-test with `make run`:
   - `make config` fails on any fragment line that didn't take, including a cut whose symbol no longer
     exists (renamed upstream).
   - `make build` fails if the config it builds isn't byte-identical to the one `make config` verified.
     That happens when the toolchain changed, which can silently drop CFI, RANDSTRUCT, KSTACK_ERASE and LTO.
   - `make check` fails on any hardening-checker FAIL that isn't in `configs/checker-accepted.txt`.
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

### 9.5 Claude Code in the VM

`make agent` and `make agent-test` require the jail (9.2) by default. Before it's set up, prefix them with `JAIL=0`
to run Firecracker and the proxy as you.

```sh
claude setup-token                       # on the host; prints a long-lived subscription token
mkdir -p ~/.config/lean-kernel && (umask 077; cat > ~/.config/lean-kernel/oauth-token)   # paste it, then ctrl-d
make agent-rootfs                        # out/rootfs-agent.ext4: the host's claude binary + bash + socat + jail-exec
make agent                               # interactive: bash as uid 10000, run `claude`; `exit` powers off
TASK='List the files in / and say what this machine is.' make agent   # headless, log in out/agent.log
```

The path: `claude` in the guest -> `127.0.0.1:8080` -> socat (as nobody, under jail-exec) -> vsock CID 2
port 8080 -> the run's `v.sock_8080` (in the jail's chroot, a hard link to the proxy's socket; unjailed,
`out/runs/<id>/v.sock_8080`) -> `scripts/api-proxy.py` on the host -> `https://api.anthropic.com`.
The guest holds only a placeholder token. The proxy swaps in the real one, forwards only `POST /v1/messages`
and `/v1/messages/count_tokens`, and logs one line per request to `out/agent-proxy.log`. It also rejects any
request that asks Anthropic's servers to reach out for the agent: server tools (`web_fetch`, `web_search`, code
execution), `mcp_servers`, and content blocks whose `source` is a URL or an uploaded file (an image or PDF "by URL"
is fetched server-side), anywhere in the messages, tool results included. Otherwise a URL with data in its query
string would be a way out. The checks are allowlists: top-level fields (`ALLOW_FIELDS`) and source types
(`ALLOW_SOURCES`: base64, text, content). A field the API adds later is refused, with its name in the DENY line,
until it's read and added. Claude Code's WebSearch tool is therefore unavailable in the VM. Log lines escape control
characters, and what headless `make agent` prints from the guest and the log has them stripped, so the guest
can't send escape sequences to your terminal. Interactive mode is the exception: the serial console reaches your
terminal raw, because filtering it would break Claude Code's full-screen interface.
Each session (one proxy process) also has a budget: 500 requests, 50M input tokens (cache reads included), 1M output
tokens and 60 requests a minute, with an optional model allowlist. Change them with `AGENT_MAX_REQUESTS`,
`AGENT_MAX_INPUT_TOKENS`, `AGENT_MAX_OUTPUT_TOKENS`, `AGENT_RPM` and `AGENT_MODELS='claude-sonnet-*'` (0 = unlimited).
Each forwarded request's log line shows its tokens and the running total, and the log ends with a session summary.
A Claude Code request costs about 16k input tokens, almost all of it cached system prompt and tool definitions.
Over budget, the agent gets a 403, which Claude Code reports as an authentication error ("Please run /login ·
API Error: 403 ..."), and stops. Over the rate,
it gets a 429 and backs off. In the guest, `/proc` is `hidepid=invisible`, so the agent sees only its own
processes, and the agent runs with `umask 077`. The guest has no other
route out. Root is read-only. `/home/agent` is a fresh 512 MB scratch drive each run, discarded at the end; `KEEP_SCRATCH=1` starts from
`out/scratch-agent.ext4` and saves the home back to it (one `KEEP_SCRATCH` run at a time: a second is refused).
The headless task and `TOOLS` arrive on a separate read-only drive written fresh each run, never from the home,
so a kept home can't replay an old task.
Runs can overlap: each works in its own `out/runs/<id>/` (VM config, socket, scratch drive, `agent.log`,
`agent-proxy.log`), `out/agent.log` and `out/agent-proxy.log` point at the newest run, and the newest 20 are kept.
`/tmp` and `/home/agent` are mounted `noexec`. With `vm.memfd_noexec=2` and no interpreter in the image that
loads native code, the agent can't run a binary it wrote, which is what most kernel exploits need. `AGENT_EXEC=1 make agent`
lifts this for workloads that build and run code. The protection weakens once the image gains Python, Node or a compiler.
VM memory is 2 GB. This needs the default kernel profile, because `VSOCK_ONLY=1` also removes loopback TCP.

**Checking the agent VM: `make agent-test`.** It boots the real agent image, but doesn't start Claude Code, and nothing it
sends is forwarded upstream, so it spends no tokens.
- **As root, from init:** the mount options (read-only root, noexec `/tmp` and home, `hidepid`, read-only `/sys`),
  the boot sysctls and the bridge.
- **As the agent, under the same `jail-exec` policy the agent gets:**
  - no capabilities and only its own processes visible;
  - `/dev/kmsg` refused;
  - no exec of a binary it wrote;
  - no TCP connect except to port 8080;
  - the proxy refusing an off-allowlist path, `web_fetch`, `mcp_servers`, a non-JSON body, URL image and document
    sources (one inside a tool result), an unknown top-level field and a malformed `Content-Length`.

Run it after changing the image, `jail-exec`, the proxy or the wrapper.

**Claude Code is pinned.** `CLAUDE_CODE_VERSION` and `CLAUDE_CODE_SHA256` in `VERSION` set the version. The image build takes it
from the host's native install and caches it in `work/claude-code/`, since the installer prunes old versions. A newer
host version is noted and ignored. To bump:
1. Install the new version on the host.
2. Run `scripts/mkrootfs-agent.sh --pin <version>` and copy the two lines it prints into `VERSION`.
3. Redo the syscall trace (6c), because the allowlist was traced against the old version.
4. Recheck the proxy's `ALLOW_FIELDS` (`scripts/api-proxy.py`): a new top-level field shows up as `API Error: 403
   field 'X' not allowed` in Claude Code and a DENY line in `out/agent-proxy.log`. Find what X does before adding it.

**Jailed (9.2).** Run `sudo scripts/jail-setup.sh` once, and `make agent` uses the jail from then on. The jail is
the default: without it, `make agent` refuses to run. `JAIL=0` runs unjailed (Firecracker and the proxy as you), and
`JAIL=auto` uses the jail if it's installed and otherwise runs unjailed with a warning. What the setup installs:
- The user `lean-proxy` (and removes `lean-fc` from an older install: Firecracker no longer has a user of its own).
- Root-owned copies of the jailer and Firecracker from the pinned release tarball, in `/usr/local/lib/lean-agent`.
  Root never runs the ones in `bin/`, because you can write to that directory.
- The wrapper, `/usr/local/sbin/lean-agent-jail`.
- `/etc/lean-agent.conf`.
- A sudoers rule that lets you run only that wrapper without a password.

Each run gets a fresh chroot under `/srv/lean-agent/firecracker/<id>/root`:
- **Firecracker** runs as a uid of its own for this run (from `FC_UID_BASE` in `/etc/lean-agent.conf`, default
  2000000000, 64 of them; no passwd entry), so two VMs running at once can't reach each other's chroot. The wrapper
  claims it under `/run/lean-agent/uids` and skips any uid with a passwd or group entry, a subuid/subgid range, a
  process, or files left by a crashed run. The chroot stays root-owned while root fills it and goes to that uid
  only just before Firecracker starts. It runs in an empty network namespace, so it has no route anywhere. A cgroup caps it
  at 2.5 GiB of memory, 64 pids and 2 CPUs, and the jailer applies an fd limit and Firecracker's own seccomp filter.
- **The proxy** runs as `lean-proxy`, with no groups, no capabilities and `no_new_privs`. The wrapper pipes the
  token to it, so `lean-proxy` never needs access to your home directory, which is mode 710 anyway.
- **Inputs:** the wrapper reads the kernel, images, config and proxy script as you and copies them into the jail,
  so root never reads a file for it that you couldn't.
- **Cleanup:** the scratch drive is copied back to the run's `out/runs/<id>/` (kept for `KEEP_SCRATCH=1`, else
  discarded), and everything else is removed. A run whose wrapper was killed outright is cleaned up by the next run.

`sudo lean-agent-jail --check` verifies the installation. After editing `scripts/lean-agent-jail`, run
`sudo scripts/jail-setup.sh` again; `sudo scripts/jail-setup.sh uninstall` removes it all. Changes to the proxy
take effect without reinstalling, because the wrapper copies `scripts/api-proxy.py` into the jail on every run.

**What the guest can make the host do.** The guest controls how much work it sends the proxy, so the proxy
bounds it. These are all set per session:
- **Connections:** at most 16 at once (`--max-connections`). A connection over the limit is closed at once and
  counted in the session summary.
- **Idle connections:** one that sends nothing for 30 s is closed (`--idle-timeout`).
- **The log:** every refused request is a line, so the log is rate-limited (a burst of 50, then 2 lines a second)
  and capped at 5000 lines (`--max-log-lines`). Dropped lines are counted and reported.
- **cgroup (jailed):** the proxy runs in its own, `lean-agent/<id>-proxy`, with 256 MiB of memory and 32 tasks
  (`PROXY_MEM_MAX`, `PROXY_PIDS_MAX` in `/etc/lean-agent.conf`).

Inside the guest, `jail-exec` caps the agent's uid at 512 processes and threads (`--nproc`, `RLIMIT_NPROC`), so a
runaway agent can't starve init or the bridge, which run as other uids.

**Proxy egress.** The wrapper resolves `api.anthropic.com` as root and passes the addresses to the proxy, which connects
to them directly. It still verifies TLS for the name, so it needs no DNS. The nftables table `inet lean_agent`, created on
the first jailed run and removed by uninstall, lets uid `lean-proxy` open TCP 443 to those addresses and rejects
everything else it sends. Firecracker also gets a file size limit (`fsize`): the scratch drive plus 64 MiB.

Not yet:
- Firecracker isn't in its own PID namespace: `--new-pid-ns` makes the jailer exit early, so the wrapper
  couldn't wait for the VM.
- No project workspace: the agent gets an empty home (or a kept one), not a copy of your repo.

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

`make check` enforces this list, which lives in `configs/checker-accepted.txt` (option, scope, reason). The scope
is `all`, a compiler (`clang`, `gcc`) or a profile (`vsock`, for `VSOCK_ONLY=1` builds only).
The checker itself is pinned (`KHC_COMMIT` in `VERSION`). To bump it, review its diff first, set the new commit,
and rerun `make check`.

Recorded 2026-10-31 against 6.18.58. First run (gcc): 50 FAILs. Now clang 22 (default): 15. gcc 14.2 (`LLVM=0`): 20.
clang is the default because it is the safer build: it adds CFI, RANDSTRUCT and KSTACK_ERASE, and it passed
the same boot test (self-test all absent, kCFI active, KASLR offsets differ per boot, clean dmesg).
The build prints 10 modpost `section mismatch` warnings from `__apply_fineibt`, `cfi_enable_callers` and `cfi_rewrite_*` -> `.init.text`; that code only
runs during boot-time alternatives patching (it would also run on module load, but MODULES=n), and boot is clean. Re-check them on each kernel or clang bump.

Not applicable to a no-PCI virtio-mmio guest:
- `X86_MCE`, `X86_MCE_INTEL`, `X86_MCE_AMD`: Firecracker doesn't forward machine checks; the host handles hardware errors.
- `INTEL_IOMMU`, `AMD_IOMMU`, `INTEL_IOMMU_DEFAULT_ON`, `INTEL_IOMMU_SVM`: no IOMMU is exposed to the guest.
- `HW_RANDOM_TPM`: no TPM. Boot entropy comes from `random.trust_cpu=on` (RDRAND); no virtio-rng device is configured.
- `WERROR`: build-time only. It buys nothing at runtime and could break a build on a newer compiler.

Chosen LSM stack (landlock, lockdown, yama):
- `SECURITY_SELINUX`, `LSM` without selinux: SELinux was cut on purpose (NOTES §3).
- `LSM_MMAP_MIN_ADDR`: only exists with SELinux. `DEFAULT_MMAP_MIN_ADDR=65536` sets the same floor.

Checker naming lag (clang build):
- `CFI_CLANG`, `CFI_PERMISSIVE`: 6.18 renamed the option to `CONFIG_CFI`; `CFI_CLANG` is a hidden
  transitional symbol. `CONFIG_CFI=y` and `CFI_PERMISSIVE` off are verified by `make config`.

vsock-only profile (`VSOCK_ONLY=1`):
- `SYN_COOKIES`: the profile has no TCP/IP, so the option doesn't exist and there is no TCP listener to
  SYN-flood. The default profile keeps it on.

Compiler-specific:
- `GCC_PLUGIN_LATENT_ENTROPY`: gcc plugins only; no clang equivalent. Boot entropy comes from
  `random.trust_cpu=on` (RDRAND). The virtio-rng driver is built in but `vm/vm.json.in` configures no
  entropy device (Firecracker's `"entropy": {}` would add one, at the cost of one more emulated device).
- gcc build only: `RANDSTRUCT_FULL`, `KSTACK_ERASE` (+`_METRICS`, `_RUNTIME_DISABLE`), `CFI_*`. These need
  clang (or gcc plugin headers, `gcc-14-plugin-dev`, for the first two). All are on in the default clang build.

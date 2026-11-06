# lean-kernel

Currently Debian focused. A minimal, hardened Linux guest kernel for running untrusted AI agents in Firecracker microVMs, one VM per agent, and a jailed setup that runs Claude Code in one: the credential stays in a host-side proxy, never in the VM.

The point: an agent that processes attacker-controlled content should not share a kernel with the host. Landlock + seccomp + an egress proxy bound what a compromised *process* can do; they are all enforced by the kernel and do not survive a kernel privilege-escalation bug. A separate, tiny guest kernel turns a kernel escape into a VM escape, a much rarer bug class, and a guest kernel with 40 drivers instead of 4,000 carries fewer of the bugs in the first place.

## Read next

- `HOWTO.md`: step by step from here to a booted guest, expected outputs, troubleshooting, cadence, what comes after.
- `NOTES.md`: why a separate kernel, what every cut and hardening option buys, honest limits, open questions.
- `~/repos/lean-kernel-devtools` (local working copy, not published): the same jail with a developer agent image (Python, Node.js, gcc/make, nasm on a Debian base). Its README lists how it differs from this repo.

## Layout

```
VERSION                  pinned kernel, Firecracker, and base-config versions
LICENSE                  Apache-2.0 (this project's own source)
THIRD-PARTY.md           licenses of the components the build fetches and the image bundles
HOWTO.md                 the procedure; NOTES.md the reasoning
configs/
  base-firecracker-x86_64-6.18.config   Firecracker's reference microvm config (upstream, unmodified)
  lean.fragment          the cuts and the gcc-safe hardening, applied on top of base
  llvm.fragment          CFI + RANDSTRUCT + KSTACK_ERASE, applied to the default clang build
  vsock-only.fragment    no TCP/IP, no NIC driver, no AF_PACKET; applied only with VSOCK_ONLY=1
  checker-accepted.txt   kernel-hardening-checker FAILs reviewed and accepted, each with its reason
scripts/
  _env.sh                shared settings for every script (paths, toolchain, VERSION)
  all.sh                 make all: every non-interactive step in order, with a timing summary
  deps-check.sh          what's missing on this host
  fetch-kernel.sh        download + verify the pinned longterm tarball into work/
  configure.sh           base + fragment(s) -> out/.config, then PROVE every fragment line stuck
  build.sh               make bzImage -> out/bzImage (bzImage, so KASLR applies)
  check.sh               run kernel-hardening-checker (KSPP) against out/.config
  mkrootfs.sh            tiny busybox ext4 root image, no root privileges needed
  run.sh                 boot it in Firecracker (serial console on this terminal)
  test.sh                boot headless with tests/probe.c as init; fail unless every wall holds
  syscalls.sh, .py       which syscalls the built vmlinux has (static, no boot)
  net-tap.sh             optional host tap for guest networking (needs sudo)
  mkrootfs-agent.sh      the agent image: pinned Claude Code, bash, socat, jail-exec, and the guest init
  run-agent.sh           boot the agent VM (interactive, headless or self-test), one out/runs/<id>/ per run
  console-filter.py      interactive console: passes the sequences the TUI needs, drops clipboard/OSC/DCS and the rest
  api-proxy.py           host-side API proxy: holds the credential, allowlists paths/headers/bodies, denylists dangerous betas, budgets
  lean-agent-jail        root wrapper: Firecracker under the jailer (uid per run), the proxy as lean-proxy
  jail-setup.sh          one-time sudo install of the wrapper, users, sudoers rule and config
  sbom.sh                SPDX + CycloneDX SBOM of the agent image with syft (make sbom)
tests/probe.c            in-guest probe: tries every cut as root, as a user, and under jail-exec
tests/console-filter-test.py  console-filter.py cases, split-read and fuzz checks
tests/api-proxy-test.py  api-proxy.py header, beta and body policy cases
tests/seccomp-test.py    the seccomp filter in api-proxy.py and console-filter.py
guest/jail-exec.c        in-guest launcher: drop to the agent uid, no_new_privs, Landlock, seccomp allowlist, exec
guest/jit-probe.c        posture probe: records whether in-process JIT (anonymous PROT_EXEC) is allowed
guest/tool-shell.c       /bin/bash in the agent image: W^X seccomp filter, then the real bash (tool shells can't JIT)
guest/agent-selftest.sh  the agent VM's hardening, checked from inside it (make agent-test)
vm/vm.json.in            Firecracker config template
docs/                    architecture diagrams (target design; as built: HOWTO §9.5)
.github/workflows/       CI: fetch, config, build, check, syscalls (no boot, nothing published)
bin/                     Firecracker release binaries (gitignored, fetched by deps-check)
work/                    kernel source + build tree (gitignored)
out/                     bzImage, vmlinux + System.map, .config, images; runs/<id>/ per agent run (gitignored)
```

## Workflow

```sh
make all       # every step below that needs no input and spends no tokens, stopping at the first failure
               # (scripts/all.sh --vsock adds the vsock-only profile; --no-agent skips the agent steps)
make deps      # lists missing packages; prints the apt line
make fetch     # kernel tarball, sha256 verified against kernel.org
make config    # merge base + lean.fragment, fail if any option was dropped by a dependency
make build     # clang build (the default); LLVM=0 make build for gcc, without CFI/RANDSTRUCT/KSTACK_ERASE
make check     # KSPP hardening checker, shows only failures
make rootfs    # 64 MB busybox ext4 image with a serial-console shell
make syscalls  # lists present and compiled-out syscalls from out/vmlinux
make test      # boots the probe guest headless; fails if any cut or hardening check doesn't hold
make run       # boots in Firecracker; ctrl-a x does nothing here, use `reboot -f` (exits Firecracker; `poweroff -f` only halts)
make agent-rootfs  # read-only image with Claude Code, bash, socat, jail-exec (root-owned, via fakeroot)
make agent     # Claude Code in the VM; credential stays in a host proxy (HOWTO §9.5); needs the jail (§9.2) or JAIL=0
make agent-test   # the agent VM's hardening, checked from inside it (no Claude Code, no tokens)
make sbom      # SPDX + CycloneDX SBOM of the agent image (needs syft; run after agent-rootfs)
```

`make config` is the step that matters. `merge_config.sh` silently lets Kconfig dependencies override a fragment line; `configure.sh` re-reads the fragment afterwards and refuses to continue if any `=y` didn't take or any `is not set` came back as built-in. A cut that didn't happen is a false sense of security.

## What gets cut (see `configs/lean.fragment` for the full list)

Modules (none; everything built in, no LKM rootkits), io_uring, user namespaces, BPF syscall, netfilter, kexec, /dev/mem, debugfs, 32-bit syscall table, legacy vsyscall, legacy (BSD) ptys, cross-process memory access, fanotify, file handles, FUSE/NFS/CIFS/9p, USB, sound, graphics, wireless, kprobes/ftrace, staging drivers. `perf_event_open` can't be cut on x86 (it's forced on), and Unix98 ptys stay; `jail-exec` refuses `perf_event_open` for the agent. With `VSOCK_ONLY=1`, also TCP/IP, the virtio NIC driver and packet sockets: the guest's only channel out is vsock. Kept: virtio block/net/console/vsock (net only in the default profile; the virtio-rng driver is built in but no entropy device is configured), ext4, serial console, seccomp, Landlock, Yama, lockdown.

## Threat model, stated plainly

Assume the agent is compromised (prompt injection is enough) and acting against you.

No claim is made that the jails are complete or correct. This is defense in depth built and reasoned about by hand; it has bugs and gaps, some known and listed below, others surely not yet found. The known-gap entries and the `make agent-test` assertions exist to keep the real posture visible, not to certify it. Read the code, run the checks, and decide for your own threat model; do not treat any layer here as a guarantee.

- Defends:
  - Reaching kernel code that isn't there, and exploit mitigations against the code that is. Inside the VM the agent is also unprivileged, under Landlock and a seccomp allowlist, on a read-only root with `noexec` writable mounts: a guest kernel bug comes before any VMM escape.
  - Credential theft: the token lives only in the host proxy; the guest holds a placeholder.
  - Exfiltration: the guest has no network, only vsock to the proxy. The proxy forwards two API paths and refuses request bodies that would make Anthropic's servers fetch anything (server tools, MCP servers, URL or file content sources), with duplicate keys refused and the checked body re-encoded before forwarding.
  - Runaway cost: per-session request, token and rate budgets.
  - The host side: Firecracker under the jailer (chroot, empty network namespace, cgroup, a uid per run); the proxy as its own user, allowed by nftables to reach only the API's addresses on 443.
- Does not defend:
  - Bugs in the virtio devices or KVM itself, or the host kernel's own LPE surface. Patch the host on its distro cadence.
  - The API itself as a channel: what the agent reads can still go to Anthropic as prompt content. The proxy stops it reaching anyone else through the API.
  - Misuse of the credential through allowed calls: budgets bound it, they don't prevent it.
  - Native code the agent generates at runtime: `noexec` and `vm.memfd_noexec=2` stop it running a binary it wrote to a file or a memfd, but not code it JITs into anonymous memory (`mmap`/`mprotect` with `PROT_EXEC` are allowed — Claude Code is itself a JIT — and nothing enforces userspace W^X). This grants nothing new at the host boundary (the agent already runs as its own uid under the same seccomp set), but it does hand native code a freer run at the guest kernel's syscall surface. `make agent-test` asserts this as a known gap; see HOWTO §9.5.
  - Interactive mode's serial console in full: `scripts/console-filter.py` drops the escape sequences that reach past the screen (OSC 52 clipboard, hyperlinks, title reports, DCS/APC strings, window moves), but cursor, colour and mode sequences pass, so the guest can still draw anything on your screen, a fake host prompt included (headless output has all control characters stripped).
- Not a general-purpose kernel. Every option kept "in case" is a bug you chose to carry.

## Cadence (the real cost)

The pinned kernel is a **longterm** series. You now own its patch cadence for this guest:

1. Weekly: `scripts/fetch-kernel.sh --check` compares `VERSION` to kernel.org's current longterm for the series.
2. On a new point release: bump `VERSION`, `make fetch config build check`, boot test, commit the `.config` diff.
3. Firecracker releases: bump `VERSION`, `make deps` re-fetches and verifies the sha256, then `sudo scripts/jail-setup.sh` installs the new binaries.
4. Claude Code: pinned in `VERSION`. A bump means a new syscall trace and a check of the proxy's field allowlist (HOWTO §9.5).

## References

- Firecracker guest configs: https://github.com/firecracker-microvm/firecracker/tree/main/resources/guest_configs
- Firecracker getting started: https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
- KSPP recommended settings: https://kspp.github.io/Recommended_Settings
- kernel-hardening-checker: https://github.com/a13xp0p0v/kernel-hardening-checker

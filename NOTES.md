# NOTES: why this repo exists, and what each decision buys

Working notes from the reading that started this (securing AI agents at the infrastructure layer:
headless containers jailed with Landlock + seccomp, a separate egress pod running Envoy, an authz
sidecar, namespace network policies). Written 2026-10-23. Revise as the reading continues.

## 1. The two jobs

The sandbox stack splits into two jobs, and the AI-specific one is the one most writeups get wrong.

| Control | Question it answers | Threat class |
|---|---|---|
| Landlock + seccomp | What can a compromised agent *process* touch on the box? | classic: attacker code runs in the container |
| Egress pod + authz sidecar + NetworkPolicy | What if the agent is *talked into* exfiltrating over a call it's allowed to make? | AI-specific: prompt injection, no breakout needed |

Prompt injection needs private data, untrusted content and one permitted path out (the "lethal
trifecta"). The egress pod is where the third leg gets cut. Landlock and seccomp contribute nothing to
that; they bound blast radius after a breakout.

Three design points that decide whether the egress pod really cuts it:

1. **It owns DNS.** If the agent namespace can resolve names directly, DNS is the exfil channel
   (OpenShell's September sandbox escape went out that way). Default-deny egress, allow only the egress
   pod, including UDP/TCP 53.
2. **CONNECT passthrough vs TLS termination is a decision, not a default.** With CONNECT, Envoy can only
   allowlist by SNI/host. If an allowed destination is general purpose (GitHub, object storage, the
   model API), the agent can still push data there. Per-tool method/path/body-size rules in ext_authz
   need TLS termination with a CA the agent trusts.
3. **Block the two in-cluster targets nobody lists:** the cloud metadata endpoint (169.254.169.254) and
   the kube API. A service-account token plus a reachable API server doesn't need the internet.

## 2. Why none of it survives a kernel bug

Every control above is enforced by the kernel. A kernel privilege-escalation bug (today's example: the
"Infinity Core" release, six Linux bugs, five giving LPE or container escape) puts attacker code in
ring 0 on the node. From there: switch namespaces, drop the seccomp filter, talk to the network as the
node. Egress pod, sidecar, NetworkPolicy are all bypassed because they only constrain traffic that
leaves through the container's network namespace. Same trust domain as the thing that broke.

What the controls *do* buy against kernel bugs: fewer reachable trigger paths. Most 2026 public Linux
LPE exploits needed one of: unprivileged user namespaces (the June nf_tables exploit, CVE-2026-23111,
needed CAP_NET_ADMIN inside a userns), io_uring, or a syscall the default seccomp profile already blocks.
A tight seccomp profile is attack-surface reduction, not containment.

What actually prevents it, in order of value:

1. **Patch cadence.** The only control that closes the bug.
2. **Shrink the kernel surface the agent can reach**, in runtime config: no unprivileged user
   namespaces, `io_uring_disabled=2`, drop all capabilities, default seccomp, `no_new_privs`.
3. **A different kernel under untrusted agents.** MicroVM per agent (Firecracker, Kata) or a user-space
   kernel (gVisor). A kernel escape becomes a guest escape, a much rarer bug class. The egress design
   sits outside the VM boundary, where it belongs.

This repo is item 3, done so that item 2 is a build-time fact instead of a runtime setting.

## 3. What each cut in `configs/lean.fragment` buys

| Cut | Why |
|---|---|
| `MODULES=n` | Nothing can be loaded after boot: no LKM rootkits, no module-signing to run, and the attack surface is exactly what's in `vmlinux`. |
| `IO_URING=n`, `USER_NS=n`, `BPF_SYSCALL=n` | The three subsystems behind most of this year's public kernel LPE PoCs. Removing the code beats disabling it with a sysctl an attacker with root can flip. |
| `KPROBES`, `UPROBES`, `FTRACE`, `PROFILING` off | Kernel introspection and patching interfaces; debug tooling the guest never needs. |
| `NETFILTER=n`, `IPV6=n`, bridge/vlan/sched off | The guest doesn't firewall or route; the egress pod does. nf_tables alone has carried several LPEs. |
| `KEXEC`, `DEVMEM`, `DEVPORT`, `PROC_KCORE`, `DEBUG_FS`, `HIBERNATION` off | Ways to replace, read or image the running kernel. |
| `IA32_EMULATION=n`, `X86_X32_ABI=n`, `LEGACY_VSYSCALL_NONE` | One syscall table. The compat tables are less exercised code with their own bug history. |
| `MODIFY_LDT_SYSCALL`, `X86_IOPL_IOPERM` off | Legacy privilege paths with no use in a headless guest. |
| `USERFAULTFD`, `KCMP`, `CHECKPOINT_RESTORE`, `KSM` off | `userfaultfd` is the standard way to win a kernel race in an exploit; the rest are process-introspection and page-merging paths an agent never uses. |
| `X86_MSR`, `X86_CPUID`, `PROC_PAGE_MONITOR`, `MAGIC_SYSRQ`, `COREDUMP` off | Root-only `/dev` and `/proc` windows into CPU state and physical memory, the serial SysRq hotkey, and core files that leak process memory. |
| `MPTCP`, `INET_DIAG` off | Multipath TCP is a second TCP stack nobody here uses; `INET_DIAG` is the socket-dump interface behind `ss`. |
| `SYSVIPC`, `POSIX_MQUEUE`, `KEYS` off | SysV `msg_msg` is the most-used heap-spray and out-of-bounds-read object in recent Linux LPEs; mqueues and keyrings are spray primitives too, and keyrings have their own LPE history. Agent runtimes use POSIX shm and futexes, not these. Takes `DNS_RESOLVER` and the trusted keyring with it (nothing here used them). |
| `NUMA` off | Single-node VM: `mbind`, `set_mempolicy`, `migrate_pages`, `move_pages` were only attack surface. |
| `QUOTA`, `SWAP` (takes zswap and hibernation), `BSD_PROCESS_ACCT` off | Root-only host administration a guest never does. Removes `quotactl`, `swapon`/`swapoff` and `acct` instead of relying on a capability check (and on `jail-exec`, which denies them too). |
| `AIO`, `RSEQ`, `KALLSYMS` off | Two more syscall families with exploit history that agent runtimes don't need (glibc falls back without rseq), and no kernel symbol table to help an exploit find its targets. Oopses are decoded on the host against `out/System.map`. |
| `XFRM_USER`, `TUN`, `PACKET`, `NETLABEL`, `UNIX_DIAG` off | IPsec netlink and AF_PACKET are recurring LPE sources; tun/tap belongs on the host; NetLabel only served SELinux/Smack. Egress is outside the VM, so the guest needs none of it. |
| `SCSI` (and with it iSCSI), `BLK_DEV_BSGLIB` (bsg), `BLK_DEV_LOOP` off | Root is virtio-blk. No SCSI stack or SG passthrough, and root can't loop-mount an image it built to reach filesystem parser bugs. |
| `HUGETLBFS`, `FS_ENCRYPTION`, `ENCRYPTED_KEYS`, `TASKSTATS` off | Unused memory, crypto and accounting interfaces. |
| BFQ/Kyber, `CPU_FREQ` (+`SCHED_MC_PRIO`, which selects it), `THERMAL`, `PTP`/`PPS` off | Dead code in a VM: the host owns frequency, thermals and clocks. |
| `SECURITY_SELINUX` off | Came in with the base config but isn't in `CONFIG_LSM`, so it was built-in dead code. |
| FUSE / NFS / CIFS / 9p / overlay / btrfs / xfs off | ext4 root only. Network and userspace filesystems are large attack surfaces reachable from unprivileged mounts. |
| USB / sound / DRM / input / wireless / BT / ACPI / PCI off | Firecracker exposes virtio over MMIO and a serial port. Everything else is dead code with drivers in it. |
| `KVM=n`, `VIRTUALIZATION=n` | No nested virtualization inside the guest. |
| `vsock-only.fragment`: `INET=n`, `VIRTIO_NET=n`, `PACKET=n` (with `VSOCK_ONLY=1`) | No TCP/IP, NIC driver or raw packet sockets in the guest. vsock is its own socket family under `NET`, not `INET`, so it still works. Costs the tap mode and any guest software that opens an IP socket. |

## 4. What each hardening option buys (gcc-safe set)

| Option | Effect |
|---|---|
| `RANDOMIZE_BASE`, `RANDOMIZE_MEMORY`, `RANDOMIZE_KSTACK_OFFSET_DEFAULT` | Attacker has to leak addresses before using them. |
| `STRICT_KERNEL_RWX`, `DEBUG_WX`, `VMAP_STACK` | No writable+executable kernel memory; stack overflows hit guard pages. |
| `STACKPROTECTOR_STRONG`, `SCHED_STACK_END_CHECK` | Canaries on most functions. |
| `SLAB_FREELIST_HARDENED`, `SLAB_FREELIST_RANDOM`, `RANDOM_KMALLOC_CACHES`, `SHUFFLE_PAGE_ALLOCATOR` (inert without `page_alloc.shuffle=1` in `boot_args`, which `vm/vm.json.in` sets), `SLAB_MERGE_DEFAULT=n` | Heap layout is unpredictable and freelist pointers are obfuscated; use-after-free and heap-spray exploits get much harder. |
| `INIT_ON_ALLOC_DEFAULT_ON`, `INIT_ON_FREE_DEFAULT_ON`, `INIT_STACK_ALL_ZERO`, `ZERO_CALL_USED_REGS` | Uninitialized-memory bugs stop leaking data; freed memory is scrubbed. Costs a few percent CPU; the guest runs one agent. |
| `HARDENED_USERCOPY` (+`_DEFAULT_ON`), `FORTIFY_SOURCE`, `UBSAN_BOUNDS` + `UBSAN_TRAP`, `BUG_ON_DATA_CORRUPTION`, `LIST_HARDENED` | Bounds and integrity checks that turn silent corruption into an immediate crash. UBSAN's bool/enum checks stay off: with trap + panic-on-oops they would turn harmless load warnings into guest panics. |
| `SLAB_BUCKETS`, `KFENCE` (sample interval 100 ms) | Separate kmalloc buckets for user-controlled allocation sizes; a low-overhead sampled detector for heap out-of-bounds and use-after-free. |
| `PAGE_TABLE_CHECK` + `_ENFORCED`, `PROC_MEM_NO_FORCE` | Catches a page mapped both writable and shared across processes (a page-table corruption exploit shape); `/proc/pid/mem` can't write past page protections. |
| `DEFAULT_MMAP_MIN_ADDR=65536`, `ARCH_MMAP_RND_BITS=32` | No mapping in the low 64 KiB (NULL-deref exploits); maximum mmap ASLR entropy. |
| `MITIGATION_SLS`, `SCHED_CORE`, `IOMMU_DEFAULT_DMA_STRICT` | Straight-line-speculation padding; SMT core scheduling (a no-op today: `vm.json.in` sets `smt: false`, so the guest has no SMT siblings); strict IOTLB flushing if an IOMMU ever appears. |
| `MITIGATION_CALL_DEPTH_TRACKING` | Compiled in as a Retbleed fallback for Skylake-family Intel cores (the i9-8950HK is one). Not in use: the guest picks IBRS, the stronger mitigation (`retbleed: Mitigation: IBRS`); call-depth tracking only runs with `retbleed=stuff`. |
| `spectre_bhi=on` (boot arg in `vm/vm.json.in`) | Without it the guest reports `BHI: Vulnerable`. In 6.18, auto mode only enables BHI clearing when the guest-to-host attack vector is mitigated, and that vector defaults to `IS_ENABLED(CONFIG_KVM)`, so `KVM=n` turned it off. Forced on, the guest reports `BHI: SW loop`: branch history is cleared on every syscall from the agent. |
| `X86_KERNEL_IBT`, `X86_USER_SHADOW_STACK` | Hardware control-flow enforcement on CPUs with CET (not the i9-8950HK; harmless there). |
| `PANIC_ON_OOPS`, `PANIC_TIMEOUT=-1` | Fail closed. An oops in a one-agent VM means restart the VM, not keep running compromised. |
| `SECURITY_LOCKDOWN_LSM` + `LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` | Even root can't read kernel memory or load unsigned code paths (and there are no modules anyway). |
| `LSM="landlock,lockdown,yama"`, `SECCOMP_FILTER` | The in-guest sandbox stack from the reading still works as the second wall. |
| `STATIC_USERMODEHELPER` with empty path | The kernel can't exec userspace helpers (`modprobe`, hotplug) on an attacker's behalf. |
| `SECURITY_DMESG_RESTRICT` | No kernel address leaks via dmesg to unprivileged users. |
| `sysctl.kernel.kptr_restrict=2` (boot arg) | `%pK` prints zeros instead of hashed pointers. Small on its own (KALLSYMS is off, `%p` already hashes), but it survives `no_hash_pointers` and a stray `%pK`. |
| `sysctl.vm.memfd_noexec=2` (boot arg) | No executable memfds, so `memfd_create` + `execveat` can't run a binary without a file. Together with the agent image's `noexec` writable mounts, the agent can't run any binary it writes. |

With the default clang build (`LLVM=0` for gcc drops these): `CFI` (6.18's name for `CFI_CLANG`; forward-edge
control-flow integrity on indirect calls, kCFI by default via `CFI_AUTO_DEFAULT=n`),
`RANDSTRUCT_FULL` (struct layouts differ per build; an exploit written for one build fails on another; only while the build stays private, see §5),
`KSTACK_ERASE` (kernel stack poisoned on syscall return, so stale stack data can't leak or be reused),
`LTO_CLANG_THIN`.

## 5. Honest limits

No claim is made that any of this is complete or correct. It is hand-built defense in depth; it has bugs
and gaps, some listed here and asserted by `make agent-test`, others not yet found. The checks keep the
posture visible, they don't certify it.

- In-process JIT defeats `noexec`/`memfd_noexec` for Claude Code's own process: it can `mmap`/`mprotect`
  anonymous memory executable and run native code generated at runtime, so the "can't run a binary it wrote"
  protection covers only file- and memfd-based exec there. It can't be closed for that process, because Claude
  Code is a Bun/JavaScriptCore JIT and needs anonymous executable memory to run JavaScript at all; closing it
  means a different mechanism and a no-JIT runtime. It is closed for everything the agent runs *through* that
  process: `/bin/bash` in the image is a launcher (`guest/tool-shell.c`) that loads a W^X seccomp filter and
  execs the real bash, so a Bash tool command and all its children can't run the Bun runtime (no `claude`
  with a `NODE_OPTIONS`/`BUN_*` preload, no `bun:ffi` TinyCC) or any other JIT. What's left is the JIT the
  model can't feed arbitrary code into. `guest/jit-probe.c` + `make agent-test` assert both halves.
  The practical impact is kernel-syscall surface, not a new host-boundary privilege (see HOWTO §9.5).
- Host-side bugs: virtio device emulation in Firecracker, KVM itself. The jailer (step 9.2 in HOWTO)
  bounds the VMM; nothing in this repo bounds KVM.
- A separate kernel is still a kernel. It will have bugs. The win is that it has far fewer of them
  reachable, and the ones that are reachable escalate to "guest root," not "node root."
- Kernel-text KASLR depends on booting `bzImage`, not `vmlinux`. The base address is chosen by the
  bzImage decompressor; Firecracker booting the bare ELF skips it (`Kernel Offset: disabled` even with
  `RANDOMIZE_BASE=y`). `make build`/`make run` use bzImage; three test boots on 2026-10-31 got offsets
  0x13000000, 0x9000000, 0x20000000. Within one VM the offset is fixed, so a guest-side info leak still defeats it.
- `RANDSTRUCT_FULL` only helps while the build stays private. The seed is random bytes from
  `/dev/urandom`, generated once per build tree at `out/scripts/basic/randstruct.seed` (gitignored), and
  anyone holding the binary can recover the struct layouts from it: `scripts/extract-vmlinux` turns a
  `bzImage` back into the full kernel, so shipping `bzImage` without `vmlinux` hides nothing that matters.
  An exploit written against a published build works on every machine running it. So:
  - Distribute the source (configs, fragments, scripts), not kernel binaries. Each host runs
    `make config build` and gets its own seed. Any binary that is published is a test build; its layout is public.
  - Never commit, copy or share `out/scripts/basic/randstruct.seed`, `out/include/generated/randstruct_hash.h`
    or a tarball of `out/`. Reproducibility settings (`KBUILD_BUILD_TIMESTAMP` etc.) don't fix the seed;
    sharing these files does.
  - The seed survives rebuilds: nothing deletes it but `make clean`. Delete it on every kernel bump
    (HOWTO §8) so one leaked layout doesn't carry over to the next version.
  - The unit is the host, not the VM: every VM on a host boots the same `out/bzImage` and shares one
    layout, so a guest that learns it (e.g. via an info leak) has it for its neighbours too.
  The other randomization (KASLR, kstack offset, slab freelist, page allocator shuffle with
  `page_alloc.shuffle=1`, stack canaries) happens at boot or at runtime and is unaffected by publishing the binary.
- Cadence is the cost. See HOWTO §8.
- This is for the agent tier only. The host machines stay on their distro kernel,
  which patches itself faster than a weekly manual check.

## 6. Open questions (answer as the reading progresses)

- vsock-only egress (no NIC in the guest at all) vs tap to an egress pod: vsock lets the guest drop
  TCP/IP and the NIC driver from its kernel, but the host-side proxy then has to speak vsock.
  Which does the reading recommend, and does Envoy do vsock natively?
  - *Partial answer (2026-10-30):* Envoy doesn't need to. Firecracker's vsock is backed by host Unix
    sockets: a guest-initiated connection to CID 2 port N arrives at `<uds_path>_N` on the host, and
    Envoy listens on a Unix socket (`pipe` address). So vsock-only is viable and lets the guest drop
    its NIC and its TCP/IP stack. Still to decide: what the reading recommends.
  - *Correction (2026-10-30):* "no NIC" is not "no network stack". The default profile still builds
    `CONFIG_NET`, `CONFIG_INET` and `CONFIG_VIRTIO_NET`; only the absent NIC in `vm.json` stops IP
    traffic. `VSOCK_ONLY=1` (`configs/vsock-only.fragment`) removes TCP/IP, the NIC driver and
    AF_PACKET from the kernel. The socket layer (`CONFIG_NET`), Unix sockets and vsock stay. In that
    profile, guest tools reach the proxy by opening `AF_VSOCK` directly (CID 2, port 8080) or through
    an AF_UNIX shim (`socat UNIX-LISTEN:/run/egress.sock,fork VSOCK-CONNECT:2:8080`, then
    `curl --unix-socket`). A loopback TCP shim needs `INET` and only works in the default profile.
    Checked by hand against 6.18.58 Kconfig: `VSOCKETS` sits under `if NET`, outside `if INET`, and
    nothing selects `INET`, `PACKET` or `VIRTIO_NET`. Since confirmed: `VSOCK_ONLY=1` builds and passes
    `make check` and `make test` (`out-vsock/`, 2026-11-01).
- Does the authz sidecar see the agent's *tool call* (structured) or only the resulting HTTP request?
  Per-tool policy needs the former, or a convention that maps tools to distinct hosts/paths.
  - *Leaning (2026-10-30):* have the agent's tools call the proxy with structured requests (tool name
    plus arguments) so policy acts on intent, not on reconstructed HTTP.
- How does the reading handle the model API endpoint itself as an exfil channel (prompt content *is*
  data leaving the sandbox)?
  - *Leaning (2026-10-30):* with local inference in its own VM (below), prompts never leave the host.
    With a remote model API, it stays an allowed path out and the proxy's size/rate limits and audit
    log are the only controls on it.
  - *As built (2026-11-01):* the API is also a path to *third* parties: a request can ask Anthropic's
    servers to fetch a URL (server tools, MCP servers, image or document blocks with a URL source).
    `scripts/api-proxy.py` refuses those, from allowlists of top-level fields and content source types,
    refuses duplicate JSON keys and forwards the re-encoded body it checked. Prompt content reaching
    Anthropic itself remains an allowed path, bounded by the budgets.

### Credentials without a separate gateway (2026-10-30)

The secret never enters the agent's trust domain. Not in env vars, the kernel cmdline, the rootfs or
the scratch drive, and not in **MMDS**: Firecracker's metadata service is guest-readable by design, the
microVM version of 169.254.169.254.

Instead, a host-side proxy on the vsock socket injects credentials. Which VM is calling is known from
which per-VM socket accepted the connection, so the guest presents nothing. The proxy attaches a
short-lived, scoped token per destination or tool (Vault or a workload-identity broker on the host,
minted per session, revoked at VM teardown) and opens TLS upstream itself. That also settles §1's
CONNECT-vs-termination point: the proxy sees full requests without a CA planted in the guest.

The proxy runs in its own jail (own uid, own netns whose only route is upstream, seccomp) and owns
DNS, allowlists, method/path/size and rate limits, the audit log, and human approval for irreversible
actions. The Firecracker process itself gets no network route.

*As built (2026-11-01, HOWTO §9.5), for one upstream (the Anthropic API):* the proxy runs as `lean-proxy`
with no groups, no capabilities and `no_new_privs`, in the host's network namespace, where nftables lets
that uid reach only the API's addresses on TCP 443. Root resolves the name, so the proxy needs no DNS. It
has no seccomp filter of its own, no per-tool tokens (one long-lived subscription token) and no human
approval step. Firecracker runs in an empty network namespace, as planned.

Limit: hiding the secret stops theft, not misuse. The agent can still use the token's authority
through allowed calls, so token scope and per-call policy are the real controls.

### GPU access (2026-10-30)

Don't give the agent VM a GPU. Put inference in its own VM with no credentials and no egress, exposing
only an inference API to the agent VM over vsock. The GPU then sits in a VM that holds only weights.

If a VM does get the GPU:

- **Full VFIO passthrough with IOMMU:** the boundary holds structurally (device DMA is confined to
  guest memory), provided IOMMU and interrupt remapping are on, the whole IOMMU group is passed with
  ACS present, the device is reset (FLR) and scrubbed between tenants, and each trust domain gets its
  own GPU (no MIG/vGPU across tenants). Residual: firmware persistence across reassignment.
- **Mediated, shared or forwarded access** (vGPU, virtio-gpu native context, gVisor nvproxy): the host
  GPU driver becomes guest-reachable attack surface. Materially weaker.
- **Plain containers:** the GPU path has already been a host escape: CVE-2024-0132 (and its bypass
  CVE-2025-23359) and CVE-2025-23266 "NVIDIAScape" in the NVIDIA Container Toolkit. The §2 problem.
- **Hypervisor:** Firecracker VFIO passthrough was landing in spring 2026 (PR #5870, `--enable-pci`),
  not confirmed in a release. Check the release notes; until then, Cloud Hypervisor or QEMU (optionally
  under Kata).
- **Cost to this repo:** a GPU guest needs `PCI=y` and an out-of-tree vendor driver, so probably
  `MODULES=y`. That is a separate kernel profile for the inference VM, not a change to
  `lean.fragment`.

Architecture diagram: `docs/architecture.html`.

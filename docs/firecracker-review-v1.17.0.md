# Firecracker v1.17.0 security review

Date: 2026-11-07. Target: Firecracker v1.17.0, commit 95f868c ("Release v1.17.0"), the version pinned in
`VERSION`. Source: `~/repos/firecracker` (shallow clone of the tag). Read-only code review, nothing built or run.

## Scope and method

The vmm crate is about 101k lines of Rust plus 6k (firecracker binary), 3k (jailer) and 0.6k (seccompiler).
The review was split into six areas, each read end to end by one reviewer following every guest-controlled
value (index, length, address, flag, port, PFN) to the point where it is used, with every `unsafe` block and
its invariant examined. The key claims were then re-verified against the source by hand. Areas:

1. virtio queue core and transports (`devices/virtio/{queue,iovec,iov_deque,device,persist}.rs`, `transport/`)
2. storage: virtio-block, vhost-user-block, sync/async engines, io_uring, pmem
3. network: virtio-net, the dumbo TCP/IP stack, MMDS, rate limiter
4. vsock (unix backend and muxer), balloon, rng, virtio-mem
5. jailer, seccomp filters (`resources/seccomp/x86_64-unknown-linux-musl.json`), main binary, signal handler
6. guest memory and vCPU (`vstate/`), buses, legacy devices, `arch/x86_64`, PCI, snapshot/restore

Threat model, as for this repo: the guest is fully attacker-controlled; the firecracker process under the
jailer is the trust boundary. High = host memory unsafety reachable from the guest, or a guest reaching host
resources beyond its configuration. Medium = guest-triggerable crash or hang of its own VMM, or a containment
gap that matters once the VMM is compromised. Low = information leaks of host state, protocol confusion.

Not reviewed (not on disk): the dependency crates `vm-memory` 0.18, `kvm-ioctls` 0.25, `kvm-bindings` 0.14,
`vmm-sys-util` 0.15, `vm-superio` 0.8 and `micro_http` (git rev 7975fe0). Every bounds argument below that
rests on `GuestMemory::get_slice` requiring the range to lie inside one region is from the crate's documented
semantics, not re-read. aarch64 was out of scope.

## Bottom line

No guest-reachable host memory-safety bug was found in any area. Every descriptor index, chain length,
sector, PFN, port and config offset traced reaches a bounds check before an unsafe pointer operation, and
descriptor fields are read once (no double fetch in the queue/iovec layer). The findings are containment
weaknesses once the VMM is compromised, guest-triggerable crashes or stalls of the guest's own VMM, and
small information leaks.

Three findings matter for this deployment (`scripts/lean-agent-jail`, `vm/vm.json.in`: virtio-block,
vsock, serial, MMIO transport, no net device by default, no balloon, no snapshots, no virtio-mem):

| # | Severity | Finding | Applies here |
|---|---|---|---|
| A | high (containment) | seccomp filter allows `io_uring_setup/enter/register` unconditionally | yes, on the Debian host (`kernel.io_uring_disabled=0`); CentOS 10 ships it disabled (2) |
| B | medium | vsock guest CONNECT does a blocking `connect()` on the VMM thread | yes: vsock is the agent's channel; proxy listen backlog is Python's default 5 |
| C | low | block GET_ID returns the backing file's `st_dev`, `st_rdev`, `st_ino` | yes |

## Findings

Severity is as assessed; "verified" means re-read at the cited lines after the area review.

### A. io_uring allowed unconditionally in the production seccomp filter (high, verified)

`resources/seccomp/x86_64-unknown-linux-musl.json`: the `vmm` thread allows `io_uring_enter`,
`io_uring_setup`, `io_uring_register` with no argument conditions (lines 66-76, comments "Used on drive
patch"); the `vcpu` thread allows `io_uring_enter` (line 1131). seccomp sees only the three entry syscalls.
The opcodes in the submission queue (`IORING_OP_OPENAT`, `SOCKET` (5.19+), `CONNECT`, `BIND`/`LISTEN`
(6.11+), `ACCEPT`, `SEND`/`RECV`, `UNLINKAT`, `RENAMEAT`, `MKDIRAT`, `SYMLINKAT`, `SETXATTR`, `SPLICE`,
`FTRUNCATE`, ...) execute without a seccomp check. So the filter's careful work, `socket` limited to
`AF_UNIX|SOCK_STREAM`, no `unlink`/`rename`/`mkdir`/`bind`/`listen`/`accept`, no INET sockets, is undone for
a compromised vmm thread, which also gains the whole io_uring kernel attack surface. The block device uses
io_uring only with `io_engine: "Async"`, which is not the default (`block/virtio/device.rs:51-56`) and which
upstream documents as not production ready, yet the shipped filter always allows it.

Scenario: a guest that has escaped into the vmm thread uses `IORING_OP_SOCKET(AF_INET)` plus `CONNECT`
and `SEND` for arbitrary egress from the jail's network namespace, or targets an io_uring kernel bug.

Here: `lean-agent-jail` passes `--netns` (a per-run namespace whose only route is the proxy), so the socket
reach is bounded to that namespace, but the filesystem opcodes and the kernel surface remain. The Debian 13
host has `kernel.io_uring_disabled=0`; CentOS Stream 10 has 2 (fully disabled), which closes this there.

Fix, operator side, both recommended:
1. `sysctl kernel.io_uring_disabled=2` on the Debian host (kernel 6.6+).
2. A custom filter: the release tarball ships `seccomp-filter-v1.17.0-x86_64.json` and
   `seccompiler-bin-v1.17.0-x86_64` (in `bin/release-v1.17.0-x86_64/`). Remove the four io_uring entries,
   compile with seccompiler-bin, place the `.bpf` in the chroot at `jail-setup`, and add
   `--seccomp-filter <file>` to the firecracker arguments in `lean-agent-jail`. The Async engine is not used
   here, so nothing breaks.
Upstream: gate the io_uring rules on the Async engine, or drop them from the default filter.

### B. vsock: guest CONNECT blocks the VMM thread in `connect()` (medium, verified)

`devices/virtio/vsock/unix/muxer.rs:637-660`: a guest `VSOCK_OP_REQUEST` for an unknown connection key
calls `UnixStream::connect("<uds_path>_<port>")` on a blocking socket; `set_nonblocking(true)` is applied
only after connect returns, and the `MAX_CONNECTIONS` (1023) check in `add_connection` (line 510) runs after
the connect. A connect to an `AF_UNIX` stream listener whose accept backlog is full blocks indefinitely
(kernel `unix_stream_connect` with the default infinite send timeout), so the guest decides when the VMM
thread parks: no virtio processing for any device, and every host-side operation serviced on that thread
stalls until the listener accepts or dies. Impact is confined to that VM's process.

Here: `scripts/api-proxy.py` is a `socketserver.ThreadingMixIn` server; its accept loop is fast (acquire a
semaphore slot or close the connection), but it uses Python's default `request_queue_size` of 5. A burst of
REQUEST packets (up to 256 per TX pass) exceeds that momentarily, so Firecracker stalls briefly until the
proxy drains the backlog, and hangs if the proxy wedges.

Fix: in the proxy, `request_queue_size = 128` on the `Server` class, and keep the accept loop free of any
blocking work. Upstream: connect with `SOCK_NONBLOCK` (treat `EAGAIN`/`EINPROGRESS` as a failed request and
send RST), or set `SO_SNDTIMEO` before connecting.

### C. Block GET_ID discloses host filesystem identifiers (low, verified)

`devices/virtio/block/virtio/device.rs:135-147` builds the 20-byte `VIRTIO_BLK_T_GET_ID` reply as
`"{st_dev}{st_rdev}{st_ino}"` of the backing file ("This is how kvmtool does it"). The guest learns the
host device and inode numbers of its root and scratch images. Fix: a hash, or an operator-supplied serial.

### D. Guest can exit its own VMM through `InvalidAvailIdx` (medium by this review's scale; intentional)

`devices/virtio/queue.rs:44-58, 479-499, 613-631`: if the driver advances `avail.idx` by more than the queue
size, `pop()` returns an error that every device turns into a process exit (block `device.rs:543, 557, 705`
unwraps; vsock, balloon, net, rng, mem propagate to exit). The comment documents this as deliberate, to stop
a hostile guest from flooding logs. `pop_unchecked` stays memory-safe regardless (the descriptor index is
re-checked at `queue.rs:120`). Effect: a guest can kill its own VM instantly. Here that is equivalent to the
agent exiting; `run-agent.sh` already treats an unexpected Firecracker exit as a failed run.

### E. `VIRTIO_BLK_T_FLUSH` is executed as `fsync` regardless of cache type (low, verified by area review)

`block/virtio/request.rs:467`: flush is executed for every drive; `cache_type` only controls whether
`VIRTIO_BLK_F_FLUSH` is advertised (`device.rs:450`) and the `Drop` behaviour. With the default
`cache_type: Unsafe`, whose docs say flushes are ignored, a guest can loop `T_FLUSH` and make the VMM thread
block in `fsync(2)` on each, charged 1 op and 0 bytes to the rate limiter. Here the drives have no rate
limiter configured, so the only bound is the guest's own progress. Fix upstream: complete flush as a no-op
when `F_FLUSH` was not negotiated. Here: a modest ops rate limiter on the scratch drive would bound it.

### F. Discard is charged 1 op and 0 bytes (low). Not applicable: `discard` is not enabled here.

`request.rs:402-419`; a single request may cover 128 MiB (`MAX_DISCARD_SECTORS`), executed as
`fallocate(PUNCH_HOLE)` on the VMM thread. Fix: charge the byte length against the bytes bucket.

### G. seccomp default action is `trap` and the handlers take locks (low, verified by area review)

`default_action: "trap"` for all three thread filters. `signal_handler.rs:22-29, 45-49, 70-73`: the
SIGSYS/SIGSEGV/SIGBUS handlers take the metrics `Mutex` and the logger `RwLock` before `_exit`. The kernel
never executes the denied syscall, so containment holds, but code already running in the process can hold
those locks and make the handler block instead of exiting, defeating the "exit code 148 plus a log line"
signal. Fix: `kill_process` as default action in a custom filter (combine with A), or lock-free handlers.

### H. `open` is unrestricted and the jail root is uid-owned (low; mitigated here)

All three thread filters allow `open` with any flags; `jailer/src/env.rs:65, 476-488` chowns `/`, `/dev`,
`/dev/net`, `/run` of the jail to the jail uid. A compromised VMM can create or modify any file inside the
jail (logs, config, writable images) and fill the host filesystem unless `--resource-limit fsize=` is set.
Here: `lean-agent-jail` passes `fsize=$FSIZE_MAX` and `no-file=1024`, so disk use is bounded.

### I. Jailer accepts `--uid 0` / `--gid 0` (low). Not applicable: the wrapper allocates a dedicated uid per run.

`jailer/src/env.rs:195-204` parses the values as `u32` with no zero check. Fix upstream: reject 0.

### J. Without `--netns`, abstract unix sockets of the host namespace are reachable (medium). Mitigated here.

`env.rs:651-653` joins a netns only if given; the filter allows `socket(AF_UNIX, SOCK_STREAM)`, `connect`
with no conditions, `sendmsg` (SCM_RIGHTS), and `ioctl(TUNSETIFF)`. Abstract sockets are scoped by network
namespace, not mount namespace. Here `--netns /run/netns/lean-<id>` is always passed, which also bounds A.

### K. virtio-mem: an unplugged slot is `PROT_NONE` but still inside `GuestMemoryMmap` (medium). Not applicable.

`vstate/vm.rs:460-475`, `vstate/memory.rs:521-534, 875`; any device access (block header `read_obj`,
queue ring pointers, iovec copies) to a GPA in a never-plugged slot passes the bounds check and faults; the
SIGSEGV handler exits the process. Documented as accepted in `docs/memory-hotplug.md`. No host memory is
read or written. This deployment configures no virtio-mem.

### L. PCI transport: a driver reset before activation does not reset the device (low). Not applicable (`pci=off`).

`transport/pci/common_config.rs:159-185` vs `transport/pci/device.rs:1181`; acked features and queue
parameters survive into the next negotiation. MMIO (`mmio.rs:181-188`) resets correctly. Guest-visible only.

### M. virtio-net: TX header TOCTOU lets MMDS-addressed frames reach the TAP (medium). Not applicable.

`devices/virtio/net/device.rs:566, 579, 609`: the MMDS/TAP decision is made on a 54-byte copy of the header
while the TAP `writev` re-reads guest memory; another vCPU can flip the destination between the two.
Documented upstream. MMDS-bound TX is also exempt from the TX rate limiter (`:585-592`). No net device is
attached here by default, and MMDS is never configured; with `NET=1`, host firewall rules on the TAP remain
the egress control, as this repo already assumes.

### N. virtio-net: RX used-descriptor counter grows while the limiter is blocked (low). Guest-only; not applicable.

`device.rs:900, 516-520, 224-230`: zero-length used entries written past the queue size wrap modulo size and
corrupt the guest's own used ring. Host writes stay inside the validated ring.

### O. Snapshot restore: XSAVE buffer length is not checked against the host's `KVM_CAP_XSAVE2` size (medium, plausible). Not applicable: no snapshots.

`arch/x86_64/vcpu.rs:705-726` (verified): `set_cpuid2(&state.cpuid)` runs first, then
`unsafe { set_xsave2(&state.xsave) }` with the comment "Safe unless the snapshot is corrupted" and no size
check. On kernels 5.17+ `KVM_SET_XSAVE` copies the guest FPU's uabi size, which grows to the AMX size once a
CPUID advertising XTILEDATA is installed, and Firecracker requests AMX guest permission at startup
(`xstate.rs:32-55`). A snapshot whose CPUID advertises AMX but whose xsave FAM is short would make the kernel
read past the Vec on an AMX host, placing adjacent heap bytes into the guest's FPU state. Kernel side not
re-read here. Fix: require the FAM length to cover `xsave2_size` before the ioctl, or copy into a fresh
buffer of that size.

### P. Snapshot restore: a crafted `plugged` bitmap makes region registration very expensive (low). Not applicable.

`vstate/vm.rs:442-452, 485-505`, `memory.rs:566-585`: `next_kvm_slot` checks only the first slot id; a
`plugged` Vec of tens of millions of entries costs a multi-GB allocation and as many syscalls before KVM
rejects. Clean error, operator-side DoS only.

### Q. Balloon config space is writable by the guest, including `num_pages` (low). Not applicable (no balloon).

`balloon/device.rs:932`; the API then reports an attacker-chosen target. Device logic does not use it.

### R. vsock: a 44-byte RX chain (zero data room) is read as "host closed" (low). Guest-only.

`vsock/csm/connection.rs:223` with `packet.rs:363`: `read_cnt == 0` moves the connection to LocalClosed
and sends SHUTDOWN although the host socket is open. The guest can only hurt its own connection.

## What was checked and found sound

- Queue: descriptor index `< queue_size` before the single raw read (`queue.rs:120, 126`); `next` validated
  before following; chain walks bounded by `ttl = queue_size`; used-ring writes index `< size` and slot
  `% size`; queue parameters only writable before activation on both transports; `queue_select` via
  `.get()`; acked features masked to offered features; config reads bounded and zero-filled.
- iovec: every descriptor range validated by `get_slice(addr, len)` before its pointer is kept; totals
  `checked_add`; `IovDeque` capacity asserted and its double mapping indexed inside `2*capacity`; every
  error path pops exactly what it pushed.
- Block: `data_len` multiple of 512, `checked_add`, `top_sector <= nsectors`; discard range fully validated;
  chain shape fixed at 2 or 3 descriptors; read-only drives are opened without write so the kernel refuses
  writes; io_uring SQ/CQ indices masked, `user_data` resolved through a slab, fds restricted to registered
  ones and ops to Read/Write/Fsync; pmem read-only is `PROT_READ` plus `KVM_MEM_READONLY`.
- vsock: 44-byte header required before any field read; `hdr.len <= 64 KiB` and `<= chain`; data copies
  bounded by `saturating_sub`; host path is `format!("{uds}_{u32}")`, numeric suffix only, so the reachable
  set is exactly `<uds_path>_<N>` inside the jail; connection table capped at 1023, RX queue 256, kill queue
  128, per-connection TX buffer 64 KiB; credit fields enter only `Wrapping` math used as a `min()` bound.
- Balloon, rng, virtio-mem: PFN lists bounded (1024 bytes, 256 PFNs), every PFN through `read_obj`, discards
  clipped per region and page-alignment checked; rng write bounded by `min(chain, 64 KiB)`; virtio-mem
  ranges block-aligned and `checked_add` against the usable region before any bitmap index.
- Net and dumbo: TX chains read-only and `<= 65562`; RX chains write-only with `min_buffer_size` so the
  `num_buffers` write lands inside the first chain; every Ethernet/ARP/IPv4/TCP length check precedes the
  read it guards; MSS option walk always advances; TCP segment writer bounds payload to the buffer and MSS;
  30 connections, 100 pending RSTs; MMDS token length capped at 70 with exact-size zerocopy parse.
- Guest memory: `PROT_NONE` reservation then `MAP_FIXED` inside it with asserted addresses; region overlap
  rejected; snapshot file size checked before mapping; memfd sealed; `discard_range` requires page-aligned
  bounds and clips per slot; MMIO/PIO reads zero-fill the exit buffer before dispatch.
- Buses: no zero-length or overflowing range, overlap rejected, lookup by `base <= addr <= end`; each device
  bounds its own access width (serial and i8042 `data.len() == 1`; MSI-X and PCI config index-checked).
- Jailer: `close_range(3..)` first, environment cleared, binary copied through an `O_NOFOLLOW` fd with
  `nlink == 1`, `id` restricted to `[A-Za-z0-9-]{1,64}`, cgroup names reject `.`/`..`/absolute, pivot_root
  then `umount2(MNT_DETACH)`, device nodes created 0600 for the jail uid, netns fd dropped after `setns`.
- seccomp: `PR_SET_NO_NEW_PRIVS` then per-thread install; load failure is fatal; all `mmap`/`mprotect`
  rules require `PROT_EXEC` clear; no `execve`, `clone`, `fork`, `ptrace`, `mount`, `setns`, `unshare`,
  `bpf`, `perf_event_open`, `userfaultfd`, `kill`, `setuid`, `capset`; `rt_sigaction` only for SIGABRT;
  vCPU threads install their filter before leaving Paused, and the vmm event loop starts only after its own.
- Release profile: `panic = "abort"`, no overflow checks; no guest-reachable arithmetic relies on an
  overflow panic for safety.

## This deployment against Firecracker's production guidance (`docs/prod-host-setup.md`)

| Recommendation | Here |
|---|---|
| Run under the jailer, dedicated uid/gid per VM | yes: `lean-agent-jail`, a uid per run from `FC_UID_BASE` |
| Jailer paths not writable by unprivileged users | yes: `/srv/lean-agent`, root-owned, checked by `--check` |
| Network namespace per VM | yes: `--netns /run/netns/lean-<id>` |
| cgroups and resource limits | yes: memory, pids, cpu via cgroup v2; `no-file=1024`, `fsize` |
| Default seccomp filter, no `--seccomp-filter` | default used; this review recommends a custom one without io_uring (A) |
| 8250 serial disabled in production, or rate limited | enabled: it is the agent console. Output is bounded by `console-filter.py` and the `"| "` prefixing in headless mode; stdout goes to a terminal or log, not an unbounded buffer |
| Disable swap | both hosts have a swap device (`/proc/swaps`); guest memory can be paged to disk |
| Disable SMT | Debian host: SMT on; `smt: false` in the machine config only hides it from the guest. CentOS 10: not supported by that host |
| Disable KSM | off on both hosts |
| io_uring | Debian: enabled (0). CentOS 10: disabled (2) |

## Recommended actions, in order

1. Compile a seccomp filter without the io_uring entries at `jail-setup` time and pass `--seccomp-filter`
   through `lean-agent-jail`; set `kernel.io_uring_disabled=2` on the Debian host as well (A). Consider
   `default_action: kill_process` in the same custom filter (G).
   Done 2026-11-07: `scripts/seccomp-filter.sh` builds the filter from the release's JSON with its
   seccompiler; every launch (`run.sh`, `test.sh`, `run-agent.sh`, `lean-agent-jail`) passes it;
   `jail-setup.sh` installs a root-owned copy; `lean-agent-jail --check` reports the io_uring sysctl.
   The sysctl itself is a host decision and is reported, not set.
2. `request_queue_size = 128` on the proxy's `Server` class (B). Done 2026-11-07.
3. Decide on swap and SMT on the Debian host (production guidance); both are host-level changes.
   `lean-agent-jail --check` now shows swap, SMT and KSM state.
4. An ops-rate limiter on the scratch drive bounds flush loops (E); not urgent. Not done: it needs guest
   root first (jail-exec denies the agent raw block access), only costs the guest its own VMM thread,
   and a limiter tight enough to matter would throttle legitimate scratch I/O.
5. Report upstream via the AWS vulnerability page named in Firecracker's `SECURITY.md`: B (blocking connect),
   C (GET_ID identifiers), E (flush on `Unsafe`), O (xsave length check), I (uid 0). A and G are design
   choices worth raising as hardening requests. K, M and D are already documented upstream as accepted.

## Reviewer coverage and limits

Six area reviews of about 180-240k tokens each, 29-55 file reads each, followed by hand verification of A,
B, C, O and the filter contents at the cited lines. Dependency crates were not on disk, so their internals
(`get_slice` single-region semantics, `FamStructWrapper` deserialization, `micro_http` request parsing, the
`register_signal_handler` `sa_mask`) are from knowledge of those versions. One `.unwrap()` on a
guest-influenced header name (`mmds/mod.rs:326`) could not be ruled out as a panic because `micro_http` was
not available; MMDS is not used here.

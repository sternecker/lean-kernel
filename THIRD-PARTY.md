# Third-party components

lean-kernel's own source (the scripts, configs, C programs, docs and tests tracked
in this repository) is licensed under Apache-2.0; see `LICENSE`.

It does not vendor any third-party code: nothing below is committed to this
repository. The components here are **fetched at build time** or **bundled into the
agent image at image-build time**, each under its own license. This file records
them for attribution and so the obligations are clear if you ever redistribute a
built artifact.

Versions are pinned in `VERSION`; the ones shown below were current at the time of
writing and may lag a bump.

## Build-time dependencies (fetched, not redistributed by this repo)

These are downloaded into `work/` and `bin/` (both gitignored) by `make fetch` /
`make deps`. This repo distributes only source that *references* them, so their
licenses impose no obligation on the lean-kernel source as committed.

| Component | Version | Upstream | License |
|-----------|---------|----------|---------|
| Linux kernel | 6.18.58 | https://www.kernel.org/ | GPL-2.0 WITH Linux-syscall-note |
| Firecracker + jailer | v1.17.0 | https://github.com/firecracker-microvm/firecracker | Apache-2.0 |
| kernel-hardening-checker | pinned to `KHC_COMMIT` in `VERSION` (b2acfd4) | https://github.com/a13xp0p0v/kernel-hardening-checker | GPL-3.0 |

The base kernel config (`configs/base-firecracker-x86_64-6.18.config`) is derived
from Firecracker's published guest config
(`resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config`, Apache-2.0).

## Bundled into the agent image

`scripts/mkrootfs-agent.sh` copies these host binaries (and their shared libraries)
into `out/rootfs-agent.ext4` (gitignored). They are **not** redistributed by this
repository, which ships source only. If you distribute the built image, you are
redistributing these binaries and must then comply with each license below —
including, for the GPL/LGPL components, providing the corresponding license texts
and a source offer, and, for Claude Code, Anthropic's own terms on redistribution.

| Component | Upstream | License |
|-----------|----------|---------|
| BusyBox | https://busybox.net/ | GPL-2.0 |
| GNU Bash | https://www.gnu.org/software/bash/ | GPL-3.0-or-later |
| socat | http://www.dest-unreach.org/socat/ | GPL-2.0 with OpenSSL exception |
| GNU C Library (glibc) | https://www.gnu.org/software/libc/ | LGPL-2.1-or-later |
| Claude Code | https://www.anthropic.com/ | Proprietary — Anthropic commercial terms |
| └ Bun runtime (inside the Claude Code binary) | https://bun.sh/ | MIT |
| └ TinyCC (embedded in Bun, used by `bun:ffi`) | https://repo.or.cz/tinycc.git | LGPL-2.1 |

glibc is pulled in as the shared libraries of the binaries above (via `ldd` in
`copy_libs`); exact versions follow the build host's distribution packages.

## Notes

- Using Linux UAPI headers (`linux/landlock.h`, `linux/seccomp.h`, etc.) in
  `guest/jail-exec.c` is covered by the kernel's `Linux-syscall-note` exception and
  does not make lean-kernel's source a derivative work of the kernel.
- `AGENT_EXEC=1` and image changes do not alter the component set above; a different
  agent image (e.g. the separate devtools image) ships a different set and needs its
  own notice file.

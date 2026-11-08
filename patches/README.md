# Kernel patches

`make fetch` applies every `*.patch` here, in name order, to the freshly extracted pinned tarball
(`scripts/fetch-kernel.sh`). The tree records the sha256 of the set it carries in
`work/linux-<version>/.lean-kernel-patched`; `make config` and `make build` refuse a tree whose set is not
the current one, and `make fetch` re-extracts a tree that carries another set instead of patching on top.
GNU `patch` applies them, or `git apply` when `patch` is not installed (RHEL 10's default).

Each patch starts with a header: what it changes, the upstream submission it comes from, why this build
needs it, and when to drop it. The rule for carrying one: an upstream fix (submitted or merged in a later
series) for something this build can observe, never a local invention. When the pinned kernel gains the
fix, `make fetch` fails to apply the patch; delete it then.

| Patch | Fixes | Upstream |
|---|---|---|
| `0001-x86-Kconfig-execmem-rox-with-strict-kernel-rwx.patch` | ITS thunk pages left writable+executable with `MODULES=n` (`DEBUG_WX`: "6 W+X pages found" on ITS-affected hosts) | Mike Rapoport, lkml 2025-09-30; 2026 resend with Fixes: 47410d839fcd, acked. Not in 6.18.62. |

Adding one: save the upstream patch as `NNNN-<topic>.patch` with the header, check it applies
(`patch -p1 --dry-run -d work/linux-<version> < patches/NNNN-*.patch`), then `make fetch config build check`
and a boot test. Rebasing after a kernel bump: regenerate the hunk against the new tree, keep the header.

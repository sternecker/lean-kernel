# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal, hardened Linux guest kernel for Firecracker microVMs, plus a jail ("AI JAIL") that runs Claude Code inside one VM per agent. The credential stays in a host-side proxy; the guest only gets vsock to it. This is security tooling: a regression in the jail, proxy, filters or config fragments is a security bug, not just a bug. `README.md` has the layout and threat model, `HOWTO.md` the procedure (§9.5 = the agent VM as built), `NOTES.md` the reasoning behind each cut and hardening option, `docs/GIT-WORKFLOW.md` the git and review rules.

Supported hosts: Debian and RHEL families only (`scripts/_env.sh` stops on anything else; `LEAN_DISTRO=debian|rhel` overrides detection). x86_64 only.

## Commands

Every `make` target is a thin wrapper over `scripts/<name>.sh`. Run the script directly when you need its options.

```sh
make all                     # every non-interactive, token-free step in order (scripts/all.sh --vsock / --no-agent)
make deps                    # missing packages + fetch/verify Firecracker into bin/
make fetch config build check  # kernel pipeline (this is what CI runs, plus `make syscalls`)
make syscalls                # syscalls present / compiled out in out/vmlinux (static, no boot)
make rootfs test             # boot the probe guest headless (needs KVM + Firecracker)
make agent-rootfs agent-test # build the agent image and check its hardening from inside (no tokens)
make agent                   # Claude Code in the VM; TASK='...' make agent for headless
make version                 # LEAN_KERNEL_VERSION, commit, and every pin
```

Build knobs (env): `LLVM=0` (gcc build, loses CFI/RANDSTRUCT/KSTACK_ERASE; default is clang ≥ `CLANG_MIN`), `VSOCK_ONLY=1` (adds `configs/vsock-only.fragment`), `LEAN_OUT=<dir>` (alternate output dir for a second profile), `LEAN_LLVM_DIR`, `JOBS`. Agent run knobs (`AGENT_SELFTEST`, `AGENT_STRACE`, `AGENT_EXEC`, budgets `AGENT_MAX_*`/`AGENT_RPM`/`AGENT_MODELS`, `JAIL=0`) are documented at the top of `scripts/run-agent.sh`.

### Tests

The tests are standalone Python scripts (no framework, no per-case selection). Run each one by itself:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/api-proxy-test.py       # proxy header/beta/body policy
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/console-filter-test.py  # escape-sequence filter, split-read, fuzz, STOK corpus
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/seccomp-test.py         # seccomp block in api-proxy.py and console-filter.py
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/tool-shell-test.py      # compiles guest/tool-shell.c without MDWE, runs probe
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/jail-policy-test.py    # static: the host-side hardening in the shell scripts stays in place
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/invisible-chars-test.py # no literal bidi/zero-width characters anywhere
shellcheck -x -P SCRIPTDIR --severity=warning scripts/*.sh scripts/lean-agent-jail guest/*.sh
```

CI (`.github/workflows/build.yml`) has two jobs: `kernel` (`make fetch config build check syscalls`) and `checks` (the tests above, shellcheck, pyflakes, cppcheck, and the guest C built with the images' `gcc -static -Wall -Wextra -Werror`). Write any invisible or bidi character as a `\uXXXX` escape, never literally. **No boot test runs in CI:** `make test` / `make agent-test` need KVM and Firecracker and must be run by hand for guest or jail changes.

## Architecture

**Kernel pipeline.** `VERSION` pins everything (kernel version + sha256, Firecracker + sha256, Claude Code + sha256, kernel-hardening-checker commit, `CLANG_MIN`, base config source); `scripts/_env.sh` sources it for every script and defines shared paths (`work/`, `out/`, `bin/`), toolchain selection, distro detection and the patch-set hash. `fetch-kernel.sh` verifies the tarball and applies `patches/*.patch`; the tree records the patch-set sha256 in `.lean-kernel-patched` and `config`/`build` refuse a tree carrying a different set. `configure.sh` merges `configs/base-firecracker-x86_64-6.18.config` (upstream, unmodified) + `lean.fragment` (+ `llvm.fragment` for clang, + `vsock-only.fragment` if set), then **re-reads every fragment line and fails if Kconfig dependencies dropped any** — this is the step that matters; never weaken it. `build.sh` requires the config to stay identical to the verified one. `check.sh` runs the pinned checker; failures not listed in `configs/checker-accepted.txt` (each with a reason) fail the build.

**Agent VM (layers, outside in).**
- Host: `scripts/lean-agent-jail` (root wrapper, installed to `/usr/local/sbin` by `sudo scripts/jail-setup.sh` along with users, sudoers rule, config and the Firecracker seccomp filter from `seccomp-filter.sh`) runs Firecracker under the jailer with a uid per run, and `scripts/api-proxy.py` as user `lean-proxy`. The proxy holds the OAuth token, allowlists API paths/headers/body fields, denylists betas and anything that makes the API fetch content (server tools, MCP, URL/file sources), rejects duplicate JSON keys, re-encodes the checked body, and enforces budgets. `scripts/console-filter.py` sits between the guest serial console and the user's terminal.
- Guest image (`scripts/mkrootfs-agent.sh`, which also contains the guest init): read-only root, `noexec` writable mounts, pinned Claude Code, socat bridging to vsock. `guest/jail-exec.c` drops to the agent uid, sets no_new_privs, Landlock and a seccomp allowlist (traced against the pinned Claude Code version), then execs. `guest/tool-shell.c` is installed as `/bin/bash`: PR_SET_MDWE + a seccomp backstop, then the real bash. `guest/agent-selftest.sh` checks this from inside (`make agent-test`), including known gaps asserted as gaps.
- `run-agent.sh` writes one `out/runs/<id>/` per run; `vm/vm.json.in` is the Firecracker config template.

## Rules for changing things (from docs/GIT-WORKFLOW.md)

- The seccomp block (`# --- seccomp: begin` … `end ---`) exists in both `api-proxy.py` and `console-filter.py` and must stay identical; change both in one commit. `tests/seccomp-test.py` checks it.
- BPF filters in `guest/jail-exec.c` / `guest/tool-shell.c`: hand-count jump offsets or simulate the filter — a wrong offset once passed every test.
- Never add a syscall to an allowlist or loosen a denylist without a stated reason and a trace (`AGENT_STRACE=1`) or test. Every new proxy field/header decision or console-filter sequence class gets a test.
- Adding a line to `configs/checker-accepted.txt` is a security decision: its own commit, with a reason. Don't disable a check to get green.
- Pin bumps in `VERSION` are single-purpose commits; produce hashes with `scripts/fetch-kernel.sh --pin`, `scripts/fetch-firecracker.sh --pin <v> --via <host>`, `scripts/mkrootfs-agent.sh --pin <v>` — never paste an unverified hash. A Claude Code bump requires a new syscall trace and a review of the proxy's field allowlist (HOWTO §6c, §9.5).
- Patches in `patches/` must be upstream fixes with the standard header (see `patches/README.md`); delete one when `make fetch` stops applying it.
- After changing `lean-agent-jail` or `jail-setup.sh`, the installed copy is separate: rerun `sudo scripts/jail-setup.sh`.
- `VERSION`'s `LEAN_KERNEL_VERSION`: bump MINOR when a security boundary changes, PATCH for fixes and docs.
- Never commit or publish `out/`, `out-*/`, `work/`, `bin/`, or any kernel binary: the RANDSTRUCT seed/layout leaks with them (this is also why CI publishes nothing).
- The repo is public and `main` is unprotected: work on a topic branch, open a PR. Commit messages for security-relevant changes are prefixed with the component (`api-proxy:`, `jail:`, `console-filter:`, `kernel:`, `ci:`, `docs:`) and say which boundary changed and why.

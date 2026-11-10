# Security policy

lean-kernel AI JAIL is a jail for AI agents: a hardened guest kernel configuration, a root-run host
jail around Firecracker, and a credential-holding API proxy, so that an untrusted agent runs in its own
microVM with nothing of yours inside it. "Jail" is meant in the chroot and FreeBSD sense (a boundary the
kernel enforces), not as a guarantee; README "Threat model, stated plainly" lists what the jail does and
does not hold. A bug in the AI jail is a security bug by default. This file says how to report one, what
is in scope, and what to expect back.

## Reporting a vulnerability

**Do not open a public issue or pull request for a vulnerability.** The repository is public, and an
issue is published the moment it is filed.

Report privately through GitHub's private vulnerability reporting, which is enabled for this repository:

- https://github.com/sternecker/lean-kernel/security/advisories/new

Include, as far as you have it:

1. The output of `make version` (this repo's version, the commit, and every pin), or the tag/commit you
   tested. Without it, assume the report is against the tip of `main`.
2. Which boundary is crossed: guest kernel, `jail-exec`/`tool-shell` (seccomp, Landlock, W^X),
   `api-proxy.py` (credential, egress policy, budgets), `lean-agent-jail`/`jail-setup.sh` (root on the
   host), `console-filter.py` (bytes reaching your terminal), the config fragments or the checker's
   accepted list.
3. Steps to reproduce: the config profile (`LLVM=0/1`, `VSOCK_ONLY=0/1`), the host distro, and a probe
   or request body that shows the gap. A failing addition to `tests/probe.c`, `guest/agent-selftest.sh`
   or `tests/*.py` is the ideal form.
4. Whether you believe the issue is already public elsewhere (an upstream CVE, a talk, a blog post).

You will get an acknowledgement within 7 days and a first assessment within 14. Fixes land on `main`
with a `sec:` commit prefix and a note in the release that carries them; `VERSION` is bumped for every
fix that changes a boundary (see the comment at the top of that file). If you want credit, say so and
how you want to be named; the default is no attribution.

If GitHub reporting is unavailable to you, open an issue titled "security contact request" with **no
details**, and a private channel will be arranged in the reply.

## Scope

In scope is anything in this repository that lets a compromised agent do what the AI jail's documented
posture says it cannot (README "Threat model, stated plainly", NOTES.md section 5 "Honest limits", HOWTO
section 9.5). Examples:

- Leaving the guest sandbox: a syscall reachable past `jail-exec`'s allowlist, a Landlock rule that
  lets the agent write where it should not, `tool-shell`'s W^X backstop being bypassable in a way its
  known-gap note does not already state.
- Reaching the credential or anything beyond the API through `api-proxy.py`: a header or body field the
  allowlist should refuse, a way to make Anthropic's servers fetch content, a budget that can be exceeded,
  a path other than the two it forwards.
- Privilege on the host: `lean-agent-jail` or `jail-setup.sh` doing something as root that the
  invoking user could not, the sudoers rule being wider than the wrapper, the seccomp filter for
  Firecracker being weaker than the release's own minus io_uring.
- A guest reaching your terminal: a control sequence that `console-filter.py` lets through and that acts
  outside the screen (clipboard, file, title report, hyperlink, keyboard remap). The STÖK payload corpus
  in `tests/console-filter-test.py` is the baseline; anything it misses is a report.
- Build-chain integrity: a pinned input (`VERSION`, `.github/workflows/build.yml`, `patches/`) that is not
  actually verified against its hash, or a `configs/*.fragment` line that `make config` reports as
  applied while the built kernel does not honour it.
- Configuration regressions: a `configs/checker-accepted.txt` entry whose reason no longer holds, or a
  hardening option the fragments claim to set that a kernel bump silently dropped.

Known, documented gaps are not vulnerabilities in this project. Before reporting, check that the
behaviour is not already listed as a limit: JIT into anonymous memory inside the guest, screen drawing
through allowed cursor and colour sequences, the API itself as a data channel, and bugs in KVM, the
host kernel or the virtio devices are all stated as out of the design's reach. A report that shows a
documented gap is **wider** than documented is in scope.

## Out of scope, report upstream instead

| Component | Where |
|-----------|-------|
| Linux kernel (the pinned longterm tarball) | security@kernel.org, https://docs.kernel.org/process/security-bugs.html |
| Firecracker and its jailer | https://github.com/firecracker-microvm/firecracker/security/policy |
| Claude Code, the Anthropic API | https://www.anthropic.com/responsible-disclosure-policy |
| kernel-hardening-checker | https://github.com/a13xp0p0v/kernel-hardening-checker/issues |
| busybox, bash, socat, glibc in the agent image | their distribution's security contact |
| Syft (SBOM tooling) | https://github.com/anchore/syft/security/policy |

If an upstream bug is only exploitable because of a choice made here (an option kept that should have
been cut, a syscall allowed that need not be), report it here as well: the pin or config is this
project's to change.

## Supported versions

There is one supported line: the tip of `main`, and the most recent tag `v<LEAN_KERNEL_VERSION>` cut from
it. Older tags receive no fixes; rebuild from `main`. The pinned kernel is a longterm series whose point
releases this project tracks on the cadence in README "Cadence"; a report against a kernel version older
than the pin in `VERSION` should first be reproduced on the pinned one.

Nothing is distributed as a binary. Every user builds the kernel and the image themselves, so a fix
reaches you only when you pull, rebuild (`make all`) and reinstall the host side
(`sudo scripts/jail-setup.sh`).

## What this project does to its own code

- `make check` runs the pinned kernel-hardening-checker against the built config; every accepted failure
  is in `configs/checker-accepted.txt` with a reason.
- `make test` and `make agent-test` boot the real kernel and image and fail unless every documented wall
  holds; the agent self-test also asserts the known gaps so they stay visible.
- `tests/*.py` cover the proxy's policy, the console filter (including the STÖK corpus and a fuzz pass),
  and the seccomp filters. CI builds and checks the kernel on every push but does not run these; see
  `docs/GIT-WORKFLOW.md` section 3 for what runs where.
- Every network input is pinned by hash in `VERSION` or by digest in the workflow, and a bump is its own
  commit. Nothing built in CI is published, because a public binary publishes the RANDSTRUCT layout.
- Reviews of third-party releases before pinning them are kept under `docs/` (for example
  `docs/firecracker-review-v1.17.0.md`).

## Safe harbour

Testing against your own build of this project is welcome and needs no permission. Do not test against
other people's hosts or sessions, and do not use a real credential you do not own. Reports made in good
faith under this policy will not be met with legal action from this project.

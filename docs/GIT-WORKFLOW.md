# Git workflow for lean-kernel (devsecops)

How to work in this repository with git when the code is security tooling: a hardened guest kernel, a
jail that runs as root on the host, and a proxy that holds a credential. A bad merge here is a security
regression, not just a bug.

Facts below were read from the repo on 2026-11-09. Re-check them with the commands in section 1 before
relying on them, because branch counts go stale in days.

## 1. What this repo looks like

| Fact | Value | Check it |
|------|-------|----------|
| Remote | `origin` = `github.com/sternecker/lean-kernel`, **public** | `git remote -v` |
| Branches on origin | `main` only | `git branch -r` |
| Local-only branches | `devtools`, `pantsdown` (never pushed) | `git branch -vv` |
| Worktrees | one per branch: `~/repos/lean-kernel`, `~/repos/lean-kernel-devtools`, `~/repos/lean-kernel-pantsdown` | `git worktree list` |
| Branch protection on `main` | none | `gh api repos/sternecker/lean-kernel/branches/main/protection` (404 = none) |
| Commit signing | not configured | `git config commit.gpgsign` (empty) |
| CI | `.github/workflows/build.yml` on every push and PR; read-only token, inputs pinned by digest. It builds the kernel and runs `make fetch config build check syscalls`. **It does not run `tests/*.py`, shellcheck, or any boot test.** | `grep -n -E 'tests/\|shellcheck' .github/workflows/build.yml` (no hits) |

Because the repo is public and `main` is unprotected, **anything you push is published immediately and a
force-push is possible by accident.** The rest of this document follows from that.

### Branch map (2026-11-09)

| Branch | Purpose | vs `main` | State |
|--------|---------|-----------|-------|
| `main` | The published line. What CI builds. | n/a | Source of truth |
| `devtools` | Same jail with a developer agent image (Python, Node, gcc, nasm on Debian). Adds `scripts/mkrootfs-dev.sh`. README says "local working copy, not published". | 1 ahead, 23 behind | Stale; predates `tool-shell.c` |
| `pantsdown` | Larger hardening line: `github-proxy.py`, agent authorization docs, full `agent-selftest`, STOK payload corpus tests. | 12 ahead, 20 behind | Tip commit is "WIP: uncommitted changes before converting to worktree" |

**Hazard, verified:** `pantsdown` still contains code that was fixed on `main` on 2026-11-09. It has
the wrong BPF jump offset in `guest/tool-shell.c` (`SET(PROT_WRITE, 3, 0)`) and the over-broad
`SCHEMA_KEYS` skip in `scripts/api-proxy.py`. A plain `git merge pantsdown` or a conflict resolved
toward "theirs" re-introduces both. See section 6.

## 2. Worktrees: one branch, one directory

Each long-lived branch lives in its own directory, so you never stash half-finished work to switch.

```bash
git worktree list                          # where each branch is checked out
git worktree add ../lean-kernel-fix-x -b fix/x main    # new topic branch in a new directory
git worktree remove ../lean-kernel-fix-x   # when the branch is merged
git worktree prune                         # forget directories you deleted by hand
```

Rules:

- A branch can be checked out in only one worktree. `git checkout pantsdown` inside the main
  directory fails by design; `cd ~/repos/lean-kernel-pantsdown` instead.
- Worktrees share one `.git` (objects, refs, config, hooks). A hook or config change applies to all.
- Build output (`out/`, `work/`, `bin/`) is per directory and gitignored. Each worktree builds its own
  kernel with its own RANDSTRUCT seed. That is correct; do not copy `out/` between them.
- `git status` in the wrong directory is the most common mistake. Check the prompt or run
  `git branch --show-current` before committing.

## 3. Daily loop

1. Start from current `main`:
   ```bash
   git fetch origin
   git switch main && git merge --ff-only origin/main
   git switch -c fix/short-name          # or feat/, sec/, docs/, chore/
   ```
2. Small commits, one concern each. A commit that changes code and a version pin together is hard to
   review and hard to revert (section 5).
3. Before every commit, run what exists in the repo:
   ```bash
   git status --short                    # nothing unexpected? no out/, no tokens, no .pyc
   git diff --cached                     # read your own diff; this is the real review for a solo repo
   PYTHONDONTWRITEBYTECODE=1 python3 -I tests/api-proxy-test.py
   PYTHONDONTWRITEBYTECODE=1 python3 -I tests/console-filter-test.py
   PYTHONDONTWRITEBYTECODE=1 python3 -I tests/seccomp-test.py
   PYTHONDONTWRITEBYTECODE=1 python3 -I tests/tool-shell-test.py
   shellcheck scripts/*.sh scripts/lean-agent-jail guest/*.sh   # installed on this host
   ```
   Kernel-side changes also need `make fetch config build check` (CI runs that chain). **CI does not
   run the Python tests or shellcheck, so green CI says nothing about the proxy, filter or jail code;
   your local run is the only gate for those.** The boot tests (`make test`, `make agent-test`) need KVM
   and Firecracker and cannot run in CI, so run them yourself before merging anything that touches
   the guest or the jail. A cheap improvement is a second CI job that runs the four `tests/*.py` files
   and shellcheck (neither needs KVM), after which "green CI" starts to mean something for those paths.
4. Push the topic branch and open a PR to `main`, even though you are the only reviewer. The PR is
   what makes CI run before the change is on `main`, and it leaves a record.
   ```bash
   git push -u origin fix/short-name
   gh pr create --fill
   gh pr checks --watch
   ```
5. Merge only when CI is green and you have re-read the diff after the last push:
   `gh pr merge --squash --delete-branch` (or `--rebase` to keep commits). Then update local `main`.

### Commit messages

Recent history is terse and lowercase ("fixed 2 bugs in the console filter"). That is fine for chores.
For anything touching a security boundary, say what boundary and why:

```
api-proxy: scope the schema skip to tool input_schema and output format

_walk skipped any key named "schema" anywhere, so a content block could hide
a URL source under it. Track where the walk is and skip only the two places
a JSON Schema belongs. Tests: tests/api-proxy-test.py (3 new cases).
```

Prefix with the component (`api-proxy:`, `jail:`, `console-filter:`, `kernel:`, `ci:`, `docs:`). Do not put
secrets, tokens, host paths with usernames, or exploit details for unfixed bugs in a message.

## 4. Secrets and things that must never be committed

This repo handles a Claude OAuth token, a kernel layout seed, and root-owned installs. Never commit:

| Item | Why | Already protected by |
|------|-----|----------------------|
| `~/.config/lean-kernel/oauth-token` or any copy | The proxy's credential | Lives outside the repo |
| `out/scripts/basic/randstruct.seed`, `out/include/generated/randstruct_hash.h`, any tarball of `out/` | Publishing the seed makes the kernel's struct layout public (NOTES section 5) | `.gitignore`: `out/`, `out-*/` |
| `bin/`, `work/`, `*.ext4`, `*.img`, `*.log` | Build artifacts, logs may echo request paths | `.gitignore` |
| `__pycache__/`, `*.pyc` | A tracked `.pyc` was found and removed on 2026-11-09 | `.gitignore` |
| `/etc/lean-agent.conf`, sudoers drop-in | Host config, written by `jail-setup.sh` | Outside the repo |
| Any kernel binary (`bzImage`, `vmlinux`) | Same layout leak as the seed | `.gitignore` via `out/` |

Guard rails to add (none of these are configured today):

- **GitHub secret scanning and push protection.** Free on public repos: Settings, Code security.
  This blocks a push containing a recognized token at the server.
- **A local pre-commit scan.** `gitleaks` and `pre-commit` are not installed on this host. Install one
  and run it on staged changes; the cheapest version is a hook that runs
  `git diff --cached -U0 | grep -E -i 'sk-ant|oauth|token|BEGIN .*PRIVATE KEY'` and fails on a hit.
- **Read `git diff --cached` every time.** Scanners miss novel formats; your eyes on the diff do not.

If a secret is committed or pushed: **rotate it first** (`claude setup-token` again; assume the old
one is burned), then clean history. Rewriting history does not un-publish a public push; the old
commit can be cached or forked. Rotation is the fix, the rewrite is cosmetic.

## 5. Security-sensitive paths and their rules

Changes under these paths get extra care. Add `.github/CODEOWNERS` listing them so GitHub requires your
review on any PR touching them (and, once collaborators exist, theirs):

| Path | Why it matters | Rule |
|------|----------------|------|
| `scripts/api-proxy.py` | Holds the credential; the egress policy | Run `tests/api-proxy-test.py`; add a test for every new field or header decision |
| `scripts/lean-agent-jail`, `scripts/jail-setup.sh` | Runs as **root** via sudoers | After merging, rerun `sudo scripts/jail-setup.sh`: the installed `/usr/local/sbin` copy is separate from the repo file |
| `guest/jail-exec.c`, `guest/tool-shell.c` | Seccomp, Landlock, W^X | Hand-count BPF jump offsets, or simulate the filter; a wrong offset passed all tests once |
| `scripts/console-filter.py` | Stops guest bytes reaching your terminal | Add a test for every new sequence class; run the STOK corpus test |
| `scripts/mkrootfs-agent.sh` (init) | The guest's trust boundary | Re-run `make agent-rootfs agent-test` |
| `VERSION` | Pins kernel, Firecracker, Claude Code, checker hashes | Pin bumps are their own commit (below) |
| `.github/workflows/` | CI with repo token | Keep `permissions: contents: read`; pin actions by full commit SHA |
| `patches/` | Kernel changes | Follow `patches/README.md` |

Specific rules:

- **Pin bumps are single-purpose commits.** Change `VERSION` (and the `.config` diff, per HOWTO) and
  nothing else. Use `scripts/fetch-kernel.sh --pin` / `scripts/fetch-firecracker.sh --pin <v> --via HOST`
  to produce the hashes; never paste a hash you did not compute from a verified download.
- **The seccomp block exists twice** (`api-proxy.py` and `console-filter.py`) and must stay identical.
  `tests/seccomp-test.py` checks it. Change both in one commit.
- **Never loosen a denylist or add a syscall to an allowlist without a reason in the commit message**
  and a trace (`AGENT_STRACE=1`) or test that shows it is needed.
- **Do not disable a failing check to get CI green.** `configs/checker-accepted.txt` lists accepted
  hardening-checker FAILs with a reason each; adding a line there is a security decision and gets its
  own reasoned commit.

## 6. Keeping long-lived branches current (pantsdown, devtools)

These branches fell behind because work continued on `main`. Merge them forward in small steps, and
treat every conflict in a security file as a review, not a chore.

Before touching either branch, make a backup you can return to:

```bash
cd ~/repos/lean-kernel-pantsdown
git branch backup/pantsdown-2026-11-09
git status --short                      # commit or stash local edits first
```

Then choose by who has seen the branch:

- **Unpublished branch (both today): rebase onto `main`.** Linear history, and the conflicts show up
  commit by commit where you can understand them.
  ```bash
  git fetch origin
  git rebase origin/main               # conflicts: resolve, `git add`, `git rebase --continue`
  git rebase --abort                   # bail out any time; nothing is lost
  ```
- **Published branch: merge, never rebase.** Rewriting shared history breaks everyone who pulled.
  ```bash
  git merge origin/main
  ```

When resolving conflicts in a security file:

1. Never pick a side wholesale (`-X theirs`, `checkout --theirs`). Read both hunks.
2. For each file touched by a recent fix on `main`, confirm the fix survives. For `pantsdown` right
   now, after the rebase these should return **0**:
   ```bash
   grep -c 'SET(PROT_WRITE, 3, 0)' guest/tool-shell.c
   grep -c 'k in SCHEMA_KEYS' scripts/api-proxy.py
   ```
3. Run every test in section 3 after each resolved commit, not just at the end.
4. `git range-diff origin/main backup/pantsdown-2026-11-09 HEAD` shows what the rebase changed versus
   your backup. Read it for dropped hunks.

`pantsdown`'s tip commit is a WIP snapshot. Before it goes anywhere, split or reword it:
`git reset --soft HEAD~1` then commit in logical pieces, or `git rebase -i` to squash and reword.

## 7. Publishing a local branch (public repo checklist)

`devtools` and `pantsdown` are unpublished on purpose. Pushing one makes its whole history public
and permanent. Before `git push -u origin <branch>`:

- [ ] `git log -p origin/main..HEAD | grep -i -E 'token|secret|password|BEGIN .*KEY'` finds nothing real.
- [ ] No WIP or "uncommitted changes" commits; messages describe the change.
- [ ] Docs describing offensive posture or agent permissions (for example
      `guest/agent-authorization*.md` on `pantsdown`) are intended for public reading.
- [ ] Every fix on `main` is present (section 6, step 2).
- [ ] All tests pass and CI will have the inputs it needs.
- [ ] You want the history, not just the tip, to be public. If not, squash to a clean branch first.

## 8. Protecting `main` (recommended, not configured)

On GitHub, Settings, Branches, add a rule for `main`:

- Require a pull request before merging.
- Require the `build` status check to pass.
- Block force pushes and deletion.
- Do not allow bypass (or accept that "include administrators" off means you can still bypass).

For a solo repo this costs one extra click per change and removes the two worst failure modes: pushing
a broken build and rewriting `main`.

Optionally sign commits so history proves who wrote it. SSH signing needs no GPG:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/<your-key>.pub
git config --global commit.gpgsign true
```

Then add the same public key to GitHub as a **signing key**, and optionally require signed commits in
the branch rule. Pick the key deliberately; this host has more than one.

## 9. Undoing things safely

| Situation | Command | Note |
|-----------|---------|------|
| Last commit message wrong, not pushed | `git commit --amend` | Only before pushing |
| Undo a commit already on `origin/main` | `git revert <sha>` | Never `reset` + force-push on `main` |
| Staged the wrong file | `git restore --staged <file>` | |
| Discard uncommitted edits to a file | `git restore <file>` | Irreversible; `git diff` first |
| Lost commits after a bad rebase or reset | `git reflog`, then `git branch rescue <sha>` | Reflog keeps ~90 days locally |
| Rebase went wrong | `git rebase --abort` | Or return to `backup/...` |
| Find which commit broke a test | `git bisect start <bad> <good>` then `git bisect run python3 -I tests/seccomp-test.py` | |
| Who changed this line and why | `git blame -L 90,95 guest/tool-shell.c`, then `git show <sha>` | |

Avoid `git push --force`. If you must (a private topic branch only), use `--force-with-lease`, which
refuses if someone else pushed in the meantime.

## 10. Quick reference

```bash
git worktree list && git branch -vv         # where everything is
git fetch origin && git status -sb          # am I behind?
git diff --cached                           # read it before you commit
gh pr create --fill && gh pr checks --watch # CI before merge
git range-diff origin/main backup/x HEAD    # what did my rebase change?
```

Order of operations for any security-relevant change: branch from fresh `main`, small commits, tests
and shellcheck, read the staged diff, PR, green CI, merge, then redeploy anything installed on the host
(`sudo scripts/jail-setup.sh`) and rerun the boot tests.

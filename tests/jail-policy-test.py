#!/usr/bin/env python3
"""Static checks that the host-side hardening in the shell scripts stays in place: python3 -I tests/jail-policy-test.py

These are text checks, not behaviour (the behaviour needs root, KVM or a booted guest: make agent-test). They exist
so a refactor can't silently drop a line that a security review asked for."""
import os
import re
import sys

sys.dont_write_bytecode = True
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
fails = 0


def src(p):
    return open(os.path.join(root, p)).read()


def check(name, ok):
    global fails
    if not ok:
        fails += 1
        print(f"FAIL {name}")


jail, run, setup, sbom = (src(f"scripts/{n}") for n in ("lean-agent-jail", "run-agent.sh", "jail-setup.sh", "sbom.sh"))

# The jailer puts Firecracker in its own PID namespace.
check("jailer: --new-pid-ns", re.search(r'"\$LIB/jailer".*--new-pid-ns', jail, re.S) is not None)
# Every directory on the token's resolved path must be unwritable by others (or sticky), not only its parent,
# and the proxy must read the path that was checked.
check("wrapper: token path walked to /", re.search(r'while \[\[ "\$d" != / \]\].*?8#022.*?8#1000.*?done', jail, re.S) is not None)
check("wrapper: proxy reads the checked token path", 'as_owner cat -- "$tok_real"' in jail and 'cat -- "$TOKEN_FILE"' not in jail)
# With --new-pid-ns the jailer exits as soon as Firecracker starts: the wrapper must wait for the VM, not the jailer.
check("wrapper: waits for the VM after the jailer exits", re.search(r'wait "\$fc".*while vm_running', jail, re.S) is not None)
# The proxy runs confined (Landlock required) in the jail.
check("wrapper: proxy needs Landlock", "--landlock require" in jail)
check("wrapper: proxy must still be running before the VM starts", re.search(r'kill -0 "\$proxy".*"\$LIB/jailer"', jail, re.S) is not None)
check("wrapper: --check probes Landlock", "/sys/kernel/security/lsm" in jail)
check("wrapper: OOM kill of the VM is not a clean exit", "oom_kill" in jail and "exit 137" in jail)
# Every guest-derived line run-agent.sh prints passes through sanitize.
check("run-agent: MANAGED-HOOKS line sanitized",
      re.search(r"grep -m1 '\^MANAGED-HOOKS='[^\n]*\| sanitize", run) is not None)
check("run-agent: refuses a wrapper without the hardening",
      "new-pid-ns" in run and "landlock require" in run)
# jail-setup hashes the copy it extracts, never bin/'s file in place.
check("setup: tarball copied before it is hashed", re.search(r'cp -- "\$t" "\$tmp/release\.tgz"', setup) is not None)
check("setup: extracts the checked copy", 'tar xzf "$tgz" -C "$tmp"' in setup and 'sha256sum -c --quiet - 2>/dev/null; then tgz="$tmp/release.tgz"' in setup)
# No network installer piped into a shell.
check("sbom: no curl | sh", not re.search(r"curl[^\n]*\|\s*(ba)?sh", sbom.replace("Do not pipe", "")))

print("FAIL" if fails else "ok", f"({fails} failures)")
sys.exit(1 if fails else 0)

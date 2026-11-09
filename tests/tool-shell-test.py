#!/usr/bin/env python3
"""Test for the seccomp filter in guest/tool-shell.c: python3 -I tests/tool-shell-test.py

Builds tool-shell with TOOL_SHELL_TEST_NO_MDWE (no PR_SET_MDWE, so the filter is the only layer) and
with tests/tool-shell-probe.c as the shell it execs, then runs it. The probe expects RWX mmap and
mprotect-to-exec to be refused with EPERM and ordinary mappings to work. x86_64 Linux only."""
import os
import platform
import subprocess
import sys
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
guest = os.path.join(here, "..", "guest")

if platform.machine() != "x86_64" or sys.platform != "linux":
    print("tool-shell-test: skipped (x86_64 Linux only)")
    sys.exit(0)

with tempfile.TemporaryDirectory() as d:
    probe, shell = os.path.join(d, "probe"), os.path.join(d, "tool-shell")
    cc = ["gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror"]
    subprocess.run(cc + ["-o", probe, os.path.join(here, "tool-shell-probe.c")], check=True)
    subprocess.run(cc + ["-DTOOL_SHELL_TEST_NO_MDWE", f'-DREAL_SHELL="{probe}"', "-o", shell,
                         os.path.join(guest, "tool-shell.c")], check=True)
    r = subprocess.run([shell], capture_output=True, text=True)

print(r.stdout, end="")
print(r.stderr, end="", file=sys.stderr)
if r.returncode != 0 or "FAIL" in r.stdout or "ok" not in r.stdout:
    print(f"tool-shell-test: FAILED (exit {r.returncode})")
    sys.exit(1)
print("tool-shell-test: ok")

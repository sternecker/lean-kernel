#!/usr/bin/env python3
"""Tests for scripts/vmci-bridge.py's policy and relay (no VMware needed): python3 -I tests/vmci-bridge-test.py"""
import importlib.util
import os
import socket
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("vb", os.path.join(here, "..", "scripts", "vmci-bridge.py"))
vb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vb)
vb.log = lambda m: None

fails = 0


def check(name, ok, detail=""):
    global fails
    if not ok:
        fails += 1
        print(f"FAIL {name} {detail}")


tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "up.sock")
echo = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
echo.bind(path)
echo.listen(8)


def serve(c):
    while True:
        d = c.recv(4096)
        if not d:
            break
        c.sendall(d.upper())
    c.close()


def echo_loop():
    while True:
        c, _ = echo.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


threading.Thread(target=echo_loop, daemon=True).start()
b = vb.Bridge([3], path, max_conns=2, idle=5)


def connect(cid):
    ours, theirs = socket.socketpair()
    return b.handle(theirs, cid), ours


def retry(cid):
    for _ in range(50):
        ok, s = connect(cid)
        if ok:
            return ok, s
        s.close()
        time.sleep(0.1)
    return False, s


ok, s = connect(3)
check("allowed cid relays", ok)
s.sendall(b"hello")
check("round trip", s.recv(100) == b"HELLO")
s.sendall(b"x" * 300_000)
got = b""
while len(got) < 300_000:
    d = s.recv(65536)
    if not d:
        break
    got += d
check("large payload both ways", got == b"X" * 300_000, len(got))

ok2, s2 = connect(4)
check("unlisted cid refused", not ok2)
check("refused connection is closed", s2.recv(10) == b"")

ok3, s3 = connect(3)
check("second slot used", ok3)
ok4, s4 = connect(3)
check("over the limit refused", not ok4)
check("over-limit connection closed", s4.recv(10) == b"")

s.shutdown(socket.SHUT_WR)
check("half-close ends relay", s.recv(10) == b"")
s.close()
s3.close()
ok5, s5 = retry(3)
check("slot freed after close", ok5)
s5.close()

# Upstream gone: the guest side is closed and the slot freed; nothing escapes to the accept loop.
os.unlink(path)
ok6, s6 = retry(3)
check("upstream down closes guest side", ok6 and s6.recv(10) == b"")

print("vmci-bridge-test:", "FAIL" if fails else "ok")
sys.exit(1 if fails else 0)

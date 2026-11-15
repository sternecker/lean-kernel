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

# A reply that takes longer than the guest's silence: the guest sends its request and then says nothing,
# the proxy answers late. The bridge must not time the guest out (it did, at 30 s, against a 600 s proxy).
check("upstream idle above the proxy's 600 s", vb.UPSTREAM_IDLE > 600, vb.UPSTREAM_IDLE)
slow_path = os.path.join(tmp, "slow.sock")
slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
slow.bind(slow_path)
slow.listen(4)


def slow_serve():
    c, _ = slow.accept()
    c.recv(100)
    time.sleep(1.5)
    c.sendall(b"late reply")
    c.close()


threading.Thread(target=slow_serve, daemon=True).start()
bs = vb.Bridge([3], slow_path, max_conns=2, idle=5)
ours, theirs = socket.socketpair()
check("slow upstream accepted", bs.handle(theirs, 3))
ours.sendall(b"request")
ours.settimeout(10)
check("late reply reaches a silent guest", ours.recv(100) == b"late reply")
check("proxy close reaches the guest", ours.recv(10) == b"")
ours.close()

# The proxy closes while the guest stays open and silent (the proxy's own idle timeout): the guest sees
# EOF and the slot comes back, instead of the bridge holding the connection forever.
quiet_path = os.path.join(tmp, "quiet.sock")
quiet = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
quiet.bind(quiet_path)
quiet.listen(4)
threading.Thread(target=lambda: quiet.accept()[0].close(), daemon=True).start()
bq = vb.Bridge([3], quiet_path, max_conns=1, idle=5)
ours, theirs = socket.socketpair()
check("quiet upstream accepted", bq.handle(theirs, 3))
ours.settimeout(10)
check("proxy close ends a silent guest's connection", ours.recv(10) == b"")
for _ in range(50):
    if bq.slots[3].acquire(blocking=False):
        bq.slots[3].release()
        freed = True
        break
    time.sleep(0.1)
else:
    freed = False
check("slot freed after proxy close", freed)
ours.close()

# A guest that sends a request and never reads the reply: the write to it times out, the connection is
# dropped and the slot comes back (it used to be held, with two threads, until the VM powered off).
flood_path = os.path.join(tmp, "flood.sock")
flood = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
flood.bind(flood_path)
flood.listen(4)


def flood_serve():
    c, _ = flood.accept()
    c.settimeout(3)
    try:
        while True:
            c.sendall(b"y" * 65536)
    except OSError:
        pass
    c.close()


threading.Thread(target=flood_serve, daemon=True).start()
bf = vb.Bridge([3, 4], flood_path, max_conns=1, idle=5, send_timeout=1)
ours, theirs = socket.socketpair()
check("stalled guest accepted", bf.handle(theirs, 3))
o4, t4 = socket.socketpair()
check("another CID has its own slots", bf.handle(t4, 4))
o4.close()
ours.sendall(b"request")
freed = False
for _ in range(80):
    if bf.slots[3].acquire(blocking=False):
        bf.slots[3].release()
        freed = True
        break
    time.sleep(0.1)
check("guest that stops reading loses its slot", freed)
ours.close()

# vmci0.id as the .vmx writes it (signed) matches the CID the kernel reports (unsigned).
bn = vb.Bridge([-565041737], path)
check("negative CID from the .vmx is allowed as its unsigned value", 3729925559 in bn.allow and vb.cid_u32(-565041737) == 3729925559)

# Refusals are logged at a bounded rate.
lim = vb.LogLimit(5)
n = sum(1 for _ in range(1000) if lim.ok()[0])
check("log limited per minute", n == 5 and lim.dropped == 995, (n, lim.dropped))

# Upstream gone: the guest side is closed and the slot freed; nothing escapes to the accept loop.
os.unlink(path)
ok6, s6 = retry(3)
check("upstream down closes guest side", ok6 and s6.recv(10) == b"")

print("vmci-bridge-test:", "FAIL" if fails else "ok")
sys.exit(1 if fails else 0)

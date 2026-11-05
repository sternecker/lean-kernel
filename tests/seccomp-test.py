#!/usr/bin/env python3
"""Tests for the seccomp filter in scripts/api-proxy.py and scripts/console-filter.py:
python3 -I tests/seccomp-test.py

Each case loads the filter in a child process (it can't be unloaded), then checks what is refused and
that what the script needs still works."""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(here, "..", "scripts")
BEGIN, END = "# --- seccomp: begin", "# --- seccomp: end ---"
fails = 0


def check(name, ok, detail=""):
    global fails
    if not ok:
        fails += 1
        print(f"FAIL {name} {detail}")


def block(name):
    s = open(os.path.join(SCRIPTS, name)).read()
    return s[s.index(BEGIN):s.index(END)]


check("seccomp block identical in both scripts", block("api-proxy.py") == block("console-filter.py"))


def load(name):
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name.split(".")[0].replace("-", "_"), os.path.join(SCRIPTS, name))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def refused(fn):
    try:
        fn()
    except PermissionError:
        return True
    except OSError as e:
        return f"OSError {e.errno}"
    return False


def in_child(body):
    """Run body() in a forked child; its result is a list of (name, ok, detail) sent back over a pipe."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            res = body()
        except BaseException as e:   # noqa: BLE001 - report anything, the parent decides
            res = [("child raised", False, repr(e))]
        os.write(w, repr(res).encode())
        os._exit(0)
    os.close(w)
    data = b""
    while chunk := os.read(r, 65536):
        data += chunk
    _, status = os.waitpid(pid, 0)
    if not data:
        return [("child died", False, f"wait status {status}")]
    import ast
    return ast.literal_eval(data.decode())


def proxy_case():
    import socket
    import ssl
    import threading
    ap = load("api-proxy.py")
    ap.install_seccomp(socket_families=(socket.AF_UNIX, socket.AF_INET, socket.AF_INET6))
    out = []
    st = open("/proc/self/status").read()
    out.append(("proxy: Seccomp: 2", "Seccomp:\t2" in st, ""))
    out.append(("proxy: execv refused", refused(lambda: os.execv("/bin/true", ["true"])) is True, ""))
    out.append(("proxy: unshare(NEWUSER) refused", refused(lambda: os.unshare(os.CLONE_NEWUSER)) is True, ""))
    out.append(("proxy: AF_PACKET refused", refused(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)) is True, ""))
    out.append(("proxy: AF_NETLINK refused", refused(lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)) is True, ""))
    out.append(("proxy: AF_VSOCK refused", refused(lambda: socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)) is True, ""))
    for fam in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6):
        try:
            socket.socket(fam, socket.SOCK_STREAM).close()
            ok = True
        except OSError:
            ok = False
        out.append((f"proxy: socket family {fam} allowed", ok, ""))
    box = []
    t = threading.Thread(target=lambda: box.append(1))
    t.start()
    t.join()
    out.append(("proxy: threads still start", box == [1], ""))
    try:
        ssl.create_default_context()
        out.append(("proxy: TLS context still builds", True, ""))
    except Exception as e:  # noqa: BLE001
        out.append(("proxy: TLS context still builds", False, repr(e)))
    return out


def console_case():
    import socket
    import fcntl
    import termios
    cf = load("console-filter.py")
    _, pty_slave = os.openpty()
    cf.install_seccomp(cf.CONSOLE_DENY, socket_families=(), threads=False)
    out = []
    out.append(("console: execv refused", refused(lambda: os.execv("/bin/true", ["true"])) is True, ""))
    out.append(("console: fork refused", refused(os.fork) is True, ""))
    out.append(("console: open refused", refused(lambda: open("/etc/hostname")) is True, ""))
    out.append(("console: socket refused", refused(lambda: socket.socket(socket.AF_UNIX)) is True, ""))
    out.append(("console: unlink refused", refused(lambda: os.unlink("/nonexistent-seccomp-test")) is True, ""))
    out.append(("console: memfd refused", refused(lambda: os.memfd_create("x")) is True, ""))
    # PermissionError means the filter refused it; with legacy_tiocsti=0 the kernel itself answers EIO.
    out.append(("console: TIOCSTI refused", refused(lambda: fcntl.ioctl(pty_slave, termios.TIOCSTI, b"x")) is True, ""))
    try:
        fcntl.ioctl(pty_slave, termios.TIOCGWINSZ, b"\0" * 8)
        out.append(("console: other ioctls still work", True, ""))
    except OSError as e:
        out.append(("console: other ioctls still work", False, repr(e)))
    f = cf.Filter()
    out.append(("console: filter still works", f.feed("a\x1b]52;c;Zm9v\x07b") == "ab", ""))
    r, w = os.pipe()
    os.write(w, b"x")
    out.append(("console: read/write on fds still work", os.read(r, 1) == b"x", ""))
    return out


if os.uname().machine != "x86_64":
    print("seccomp-test: skipped (x86_64 only)")
    sys.exit(0)
for case in (proxy_case, console_case):
    for name, ok, detail in in_child(case):
        check(name, ok, detail)
print(f"seccomp: {'ok' if not fails else 'FAILED'} ({fails} failures)")
sys.exit(1 if fails else 0)

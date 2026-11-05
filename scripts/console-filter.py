#!/usr/bin/env python3
"""Filter the interactive agent VM's serial console on its way to the host terminal.

The guest controls every byte on ttyS0, and Claude Code's full-screen interface needs real escape
sequences, so stripping all control characters (as headless mode does) is not an option. Instead this
parses the stream the way a terminal does and re-emits only sequences on an allowlist, rebuilt from
their parsed parts, so the terminal never sees a malformed or partial sequence that it might parse
differently than we did. Sequences split across reads are held until they complete.

Passed:
  - printable text, TAB, LF, CR, BS, BEL
  - CSI sequences (cursor, SGR colours, modes, mouse and keyboard protocols, numeric queries), except
    window operations (CSI t) other than size reports and title push/pop, and media copy (CSI i)
  - two-character ESC sequences (ESC 7, ESC =, ESC ( B, ...)
  - OSC 0/1/2 (window title), with control and bidi characters removed from the title
  - OSC 10/11/12 ;? (foreground/background/cursor colour queries; the reply holds only colour values)

Dropped:
  - every other OSC: 52 (clipboard write and read), 8 (hyperlinks), 4/10/11/12 colour changes,
    7 (cwd), 9/99/777 (notifications), 133, 1337 (iTerm2), ...
  - DCS, APC, PM and SOS strings (DECRQSS, sixel, kitty graphics, tmux passthrough, ...)
  - CSI 20 t / 21 t (title reports: the reply would echo guest-chosen text into the terminal's input),
    and window moves, resizes, raises and iconify
  - other C0 controls, DEL, C1 controls (8-bit CSI/OSC/DCS included) and the bidi/format characters
    that reorder or hide text (U+061C, U+200B-U+200F except U+200D, U+202A-U+202E, U+2066-U+2069, U+FEFF)

At end of input it resets terminal state the guest may have left behind: attributes, character set,
alternate screen, hidden cursor, mouse and focus reporting, bracketed paste, kitty keyboard flags.
"""
import codecs
import os
import re
import sys

ESC = "\x1b"
# Ground state: a run of characters that pass unchanged. Not ESC (handled separately), not other C0
# except BEL BS TAB LF CR, not DEL or C1, not the bidi/format controls. U+200D (ZWJ) stays: emoji use it.
UNSAFE = "\x00-\x06\x0b\x0c\x0e-\x1f\x7f-\x9f؜​‌‎‏‪-‮⁦-⁩﻿"
SAFE_RUN = re.compile(f"[^{UNSAFE}]+")
UNSAFE_CHAR = re.compile(f"[{UNSAFE}\x07-\x0a\x0d]")  # for titles: no controls at all

MAX_CSI = 128    # longest CSI kept; longer ones are dropped (truecolour SGR is ~40)
MAX_OSC = 512    # longest OSC payload kept; longer ones are dropped (titles are short)
# CSI Ps t window operations that only report sizes (numbers) or push/pop the title stack.
WINOPS_OK = {"14", "16", "18", "22", "23"}

RESET = (
    "\x1b[0m"        # attributes
    "\x1b(B"         # G0 = ASCII (undo ESC ( 0 line drawing)
    "\x1b[?2026l"    # synchronized output off
    "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l"  # mouse reporting off
    "\x1b[?1004l"    # focus reporting off
    "\x1b[?2004l"    # bracketed paste off (the host shell's readline turns it back on)
    "\x1b[<99u"      # pop kitty keyboard protocol flags
    "\x1b[?1049l"    # back to the main screen
    "\x1b[?25h"      # cursor visible
)

GROUND, ESCAPE, ESC_INTER, CSI, OSC, OSC_ESC, STRING, STRING_ESC, DISCARD = range(9)


class Filter:
    def __init__(self):
        self.state = GROUND
        self.buf = []

    def feed(self, s):
        out = []
        i, n = 0, len(s)
        while i < n:
            if self.state == GROUND:
                m = SAFE_RUN.match(s, i)
                if m:
                    out.append(m.group())
                    i = m.end()
                    continue
                c = s[i]
                i += 1
                if c == ESC:
                    self.state, self.buf = ESCAPE, []
                # anything else here is an unsafe character: dropped
                continue
            c = s[i]
            i += 1
            if not self.step(c, out):
                i -= 1   # c ended a sequence without belonging to it: process it again in GROUND
        return "".join(out)

    def step(self, c, out):
        """Advance one character inside a sequence. False: c was not consumed."""
        o = ord(c)
        st = self.state
        if st == ESCAPE:
            if c == "[":
                self.state, self.buf = CSI, []
            elif c == "]":
                self.state, self.buf = OSC, []
            elif c in "P_^X":                       # DCS, APC, PM, SOS
                self.state = STRING
            elif 0x20 <= o <= 0x2F:                 # ESC intermediate ... final, e.g. ESC ( B
                self.state, self.buf = ESC_INTER, [c]
            elif 0x30 <= o <= 0x7E:                 # ESC 7, ESC 8, ESC =, ESC >, ESC M, ESC c, ...
                out.append(ESC + c)
                self.state = GROUND
            else:                                   # control or non-ASCII after ESC: drop the ESC
                self.state = GROUND
                return False
            return True
        if st == ESC_INTER:
            if 0x20 <= o <= 0x2F and len(self.buf) < 4:
                self.buf.append(c)
            elif 0x30 <= o <= 0x7E:
                out.append(ESC + "".join(self.buf) + c)
                self.state = GROUND
            else:
                self.state = GROUND
                return False
            return True
        if st == CSI:
            if 0x40 <= o <= 0x7E:
                self.csi_done("".join(self.buf), c, out)
                self.state = GROUND
            elif 0x20 <= o <= 0x3F and len(self.buf) < MAX_CSI:
                self.buf.append(c)
            else:   # control, non-ASCII or too long: drop the whole sequence
                self.state = GROUND
                return 0x20 <= o <= 0x3F   # an over-long CSI's own bytes are consumed
            return True
        if st == OSC:
            if c == "\x07" or c == "\x9c":
                self.osc_done("".join(self.buf), out)
                self.state = GROUND
            elif c == ESC:
                self.state = OSC_ESC
            elif len(self.buf) < MAX_OSC:
                self.buf.append(c)
            else:
                self.state = DISCARD
            return True
        if st == OSC_ESC:
            self.state = GROUND
            if c == "\\":
                self.osc_done("".join(self.buf), out)
                return True
            # ESC not followed by \ ends the OSC (dropped) and starts a new sequence
            self.state, self.buf = ESCAPE, []
            return False
        if st in (STRING, DISCARD):   # dropped until its terminator
            if c == "\x9c" or (st == DISCARD and c == "\x07"):
                self.state = GROUND
            elif c == ESC:
                self.state = STRING_ESC
            return True
        if st == STRING_ESC:
            if c == "\\":
                self.state = GROUND
                return True
            self.state, self.buf = ESCAPE, []
            return False
        raise AssertionError(st)

    @staticmethod
    def csi_done(body, final, out):
        # body: parameter bytes (0x30-0x3F) then intermediates (0x20-0x2F); reject other orders.
        m = re.fullmatch(r"([0-?]*)([ -/]*)", body)
        if not m:
            return
        params, inter = m.groups()
        if final == "i":   # media copy: printing
            return
        if final == "t" and not inter:
            if params[:1] in ("<", "=", ">", "?"):
                return
            if params.split(";")[0] not in WINOPS_OK:
                return
        out.append(ESC + "[" + body + final)

    @staticmethod
    def osc_done(payload, out):
        num, sep, rest = payload.partition(";")
        if num in ("0", "1", "2") and sep:
            out.append(ESC + "]" + num + ";" + UNSAFE_CHAR.sub("", rest) + ESC + "\\")
        elif num in ("10", "11", "12") and rest == "?":
            out.append(ESC + "]" + num + ";?" + ESC + "\\")


def write_all(fd, data):
    while data:
        data = data[os.write(fd, data):]


# --- seccomp: begin (kept identical in scripts/api-proxy.py and scripts/console-filter.py; ---
# --- tests/seccomp-test.py checks that) ---
# A host process that parses guest-controlled bytes gets a seccomp filter once it has set itself up. It
# is a denylist that answers EPERM, not an allowlist that kills: CPython with threads and TLS uses
# syscalls nobody wants to enumerate, and a miss must not take the console or the proxy down mid-run.
# What it removes is the kernel surface a compromised process would reach for next: exec, debugging other
# processes, namespaces and mounts, bpf, io_uring, userfaultfd, perf, keyrings, modules, kexec, terminal
# input injection (TIOCSTI). x86_64
# only, like the rest of the repo (Firecracker's release binaries are x86_64); anything else refuses to
# start rather than run unfiltered. Standard library only (ctypes): the scripts run under python3 -I.
SECCOMP_DENY_COMMON = {
    "execve": 59, "execveat": 322, "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
    "process_madvise": 440, "pidfd_getfd": 438, "personality": 135,
    "unshare": 272, "setns": 308, "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
    "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "move_mount": 429, "open_tree": 428,
    "open_tree_attr": 467, "mount_setattr": 442,
    "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246, "kexec_file_load": 320,
    "open_by_handle_at": 304, "name_to_handle_at": 303, "swapon": 167, "swapoff": 168, "reboot": 169,
    "acct": 163, "quotactl": 179,
}
_NR_CLONE, _NR_CLONE3, _NR_SOCKET, _NR_IOCTL = 56, 435, 41, 16
# ioctls that act on another process's input: TIOCSTI pushes bytes into a terminal's input queue (the
# console filter's stdout is the user's terminal, so that would type commands into their shell), and
# TIOCLINUX can do the same on a virtual console. Refused even where dev.tty.legacy_tiocsti=0.
_IOCTL_DENY = (0x5412, 0x541C)   # TIOCSTI, TIOCLINUX
# CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET
_CLONE_NS = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000


def install_seccomp(extra_deny=(), socket_families=None, threads=True):
    """Load the filter into this process (all its threads). extra_deny: more syscall numbers to refuse.
    socket_families: the address families socket() may create (an empty tuple refuses socket() outright;
    None leaves it alone). threads=False refuses clone() too; otherwise clone() may make threads but no
    namespaces. clone3() answers ENOSYS, so glibc falls back to clone(), whose flags a filter can read.
    Raises OSError if the filter could not be loaded: callers stop rather than run without it."""
    import ctypes
    import struct

    if os.uname().machine != "x86_64":
        raise OSError(f"seccomp filter: x86_64 only, not {os.uname().machine}")
    LD, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06   # BPF_LD|W|ABS, BPF_JMP|{JEQ,JGE,JSET}|K, BPF_RET|K
    KILL, ALLOW = 0x80000000, 0x7FFF0000                      # SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ALLOW
    EPERM, ENOSYS = 0x00050000 | 1, 0x00050000 | 38           # SECCOMP_RET_ERRNO | errno
    prog = [
        (LD, 0, 0, 4), (JEQ, 1, 0, 0xC000003E), (RET, 0, 0, KILL),   # arch must be AUDIT_ARCH_X86_64
        (LD, 0, 0, 0), (JGE, 0, 1, 0x40000000), (RET, 0, 0, KILL),   # no x32 numbers past the denylist
    ]
    for nr in sorted(set(SECCOMP_DENY_COMMON.values()) | set(extra_deny)):
        prog += [(JEQ, 0, 1, nr), (RET, 0, 0, EPERM)]
    prog += [(JEQ, 0, 1, _NR_CLONE3), (RET, 0, 0, ENOSYS)]
    # ioctl: args[1] low word (offset 24) is the request
    prog += [(JEQ, 0, len(_IOCTL_DENY) + 3, _NR_IOCTL), (LD, 0, 0, 24)]
    prog += [(JEQ, len(_IOCTL_DENY) - i, 0, c) for i, c in enumerate(_IOCTL_DENY)]
    prog += [(RET, 0, 0, ALLOW), (RET, 0, 0, EPERM)]
    if threads:   # args[0] low word (offset 16): the flags
        prog += [(JEQ, 0, 4, _NR_CLONE), (LD, 0, 0, 16), (JSET, 0, 1, _CLONE_NS), (RET, 0, 0, EPERM), (RET, 0, 0, ALLOW)]
    else:
        prog += [(JEQ, 0, 1, _NR_CLONE), (RET, 0, 0, EPERM)]
    if socket_families is not None:
        fams = list(socket_families)
        prog += [(JEQ, 0, len(fams) + 3, _NR_SOCKET), (LD, 0, 0, 16)]
        prog += [(JEQ, len(fams) - i, 0, f) for i, f in enumerate(fams)]
        prog += [(RET, 0, 0, EPERM), (RET, 0, 0, ALLOW)]
    prog.append((RET, 0, 0, ALLOW))

    buf = ctypes.create_string_buffer(b"".join(struct.pack("<HBBI", *i) for i in prog))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog), ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    # PR_SET_NO_NEW_PRIVS: required to load a filter without CAP_SYS_ADMIN, and nothing here needs privs.
    if libc.prctl(38, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
    # seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog): every thread, or none.
    rc = libc.syscall(ctypes.c_long(317), ctypes.c_long(1), ctypes.c_long(1), ctypes.byref(fprog))
    if rc != 0:
        raise OSError(ctypes.get_errno(), f"seccomp(SECCOMP_SET_MODE_FILTER) returned {rc}")
# --- seccomp: end ---


# Beyond the common list: the console filter only reads fd 0 and writes fd 1, so once it is running it
# needs no new files, no sockets and no processes. It runs as the user, so this keeps a compromised filter
# from creating or changing any of the user's files.
CONSOLE_DENY = (
    2, 257, 437, 85,            # open, openat, openat2, creat
    87, 263, 82, 264, 316,      # unlink, unlinkat, rename, renameat, renameat2
    86, 265, 88, 266, 76,       # link, linkat, symlink, symlinkat, truncate
    90, 268, 452, 92, 94, 260,  # chmod, fchmodat, fchmodat2, chown, lchown, fchownat
    133, 259, 83, 258, 84,      # mknod, mknodat, mkdir, mkdirat, rmdir
    188, 189, 197, 198, 463, 466,  # setxattr, lsetxattr, removexattr, lremovexattr, setxattrat, removexattrat
    280, 235, 132, 261,         # utimensat, utimes, utime, futimesat
    319, 57, 58,                # memfd_create, fork, vfork
)


def main():
    f = Filter()
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        install_seccomp(CONSOLE_DENY, socket_families=(), threads=False)
    except OSError as e:
        sys.exit(f"console-filter: {e}; not running without the seccomp filter")
    try:
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                break
            text = f.feed(dec.decode(chunk))
            if text:
                write_all(1, text.encode("utf-8"))
        write_all(1, (f.feed(dec.decode(b"", final=True)) + RESET).encode("utf-8"))
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit("usage: console-filter.py < guest-output > terminal")
    main()

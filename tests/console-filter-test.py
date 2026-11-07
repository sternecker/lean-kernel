#!/usr/bin/env python3
"""Tests for scripts/console-filter.py: python3 -I tests/console-filter-test.py"""
import importlib.util
import os
import random
import sys

sys.dont_write_bytecode = True
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cf", os.path.join(here, "..", "scripts", "console-filter.py"))
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)

E, ST = "\x1b", "\x1b\\"
CASES = [
    # (input, expected output)
    ("hello\r\n\tok\x07\b", "hello\r\n\tok\x07\b"),
    ("a\x00b\x0ec\x7fd\x9be\x1af", "abcdef"),
    (f"{E}[1;38;2;10;20;30mX{E}[0m", f"{E}[1;38;2;10;20;30mX{E}[0m"),
    (f"{E}[?1049h{E}[?2026h{E}[2J{E}[H{E}[>1u{E}[?u{E}[c{E}[6n", f"{E}[?1049h{E}[?2026h{E}[2J{E}[H{E}[>1u{E}[?u{E}[c{E}[6n"),
    (f"{E}7{E}8{E}={E}(0{E}(B", f"{E}7{E}8{E}={E}(0{E}(B"),
    # clipboard: write and read, BEL and ST terminated, and the 8-bit OSC form
    (f"a{E}]52;c;ZWNobyBwd25lZAo=\x07b", "ab"),
    (f"a{E}]52;c;?{ST}b", "ab"),
    ("a\x9d52;c;Zm9v\x9cb", "a52;c;Zm9vb"),   # 8-bit OSC/ST dropped; payload is just text
    # other OSCs dropped; titles kept with controls stripped; colour queries kept, sets dropped
    (f"{E}]8;;https://evil/{ST}link{E}]8;;{ST}", "link"),
    (f"{E}]2;my‮title{ST}", f"{E}]2;mytitle{ST}"),
    (f"{E}]0;t\x07", f"{E}]0;t{ST}"),
    (f"{E}]11;?\x07{E}]11;rgb:0/0/0\x07", f"{E}]11;?{ST}"),
    (f"{E}]1337;File=x\x07{E}]777;notify;a;b\x07", ""),
    # DCS / APC / PM / SOS dropped
    (f"a{E}P$qm{ST}b{E}_Gf=100;AAAA{ST}c{E}^pm{ST}d", "abcd"),
    # window ops: title reports, moves, resizes and title push/pop dropped; size reports kept
    (f"{E}[21t{E}[20t{E}[3;0;0t{E}[8;999;999t{E}[18t{E}[22;0t{E}[23;0t{E}[>2t", f"{E}[18t"),
    # private modes: VT52 (?2) and 132 columns (?3) dropped in any position; other modes kept
    (f"{E}[?2l{E}[?3h{E}[?1;3l{E}[?2;25h{E}[?1h{E}[?25l{E}[?1049h{E}[4h{E}[2h", f"{E}[?1h{E}[?25l{E}[?1049h{E}[4h{E}[2h"),
    (f"{E}[5i{E}[?4i", ""),
    # an OSC cut short by another ESC is dropped, and the new sequence is parsed
    (f"{E}]2;x{E}]52;c;Zm9v\x07ok", "ok"),
    # CAN inside a CSI: sequence dropped
    (f"{E}[3\x182J", "2J"),
    # bidi/format controls stripped from text, ZWJ kept
    ("a‮b⁦c​d﻿‍", "abcd‍"),
]


def run(chunks):
    f = cf.Filter()
    return "".join(f.feed(c) for c in chunks)


failed = 0
for inp, want in CASES:
    got = run([inp])
    # Any split of the input across reads must give the same output.
    splits = [[inp[:k], inp[k:]] for k in range(len(inp) + 1)] + [list(inp)]
    bad = [s for s in splits if run(s) != got]
    if got != want or bad:
        failed += 1
        print(f"FAIL {inp!r}\n  want {want!r}\n  got  {got!r}" + (f"\n  split-dependent: {bad[0]!r}" if bad else ""))

# Fuzz: whatever the guest sends, the output must contain no OSC other than titles and colour
# queries, no string controls, and no bytes the filter is meant to drop.
rng = random.Random(1)
alphabet = ["\x1b", "[", "]", "P", "_", "\\", "\x07", "\x9c", "\x9b", "\x9d", ";", "5", "2", "c", "?", "t",
            "i", "m", "2", "1", "0", "\x18", "\x00", "a", " ", "(", "‮"]
for _ in range(20000):
    s = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
    out = run([s])
    j = 0
    while True:
        j = out.find("\x1b", j)
        if j < 0:
            break
        nxt = out[j + 1:j + 2]
        if nxt in ("P", "_", "^", "X") or (nxt == "]" and not (out.startswith("\x1b]0;", j) or out.startswith("\x1b]1;", j) or out.startswith("\x1b]2;", j) or out.startswith("\x1b]1", j) and out[j+2:j+5] in ("0;?", "1;?", "2;?"))):
            failed += 1
            print(f"FAIL fuzz {s!r} -> {out!r}")
            break
        if nxt == "[" and (out[j:].startswith("\x1b[21t") or out[j:].startswith("\x1b[20t")):
            failed += 1
            print(f"FAIL fuzz title report {s!r} -> {out!r}")
            break
        j += 1
    if any(ch in out for ch in "\x00\x18\x9b\x9c\x9d‮"):
        failed += 1
        print(f"FAIL fuzz control {s!r} -> {out!r}")

# START/RESET bracket the session: title pushed, then popped; the soft reset and scroll region reset are
# in RESET, and nothing in RESET is a sequence the filter itself would drop.
if cf.START != f"{E}[22;0t" or not cf.RESET.endswith(f"{E}[23;0t") or f"{E}[!p" not in cf.RESET or f"{E}[r" not in cf.RESET:
    failed += 1
    print("FAIL START/RESET title push/pop or soft reset missing")
for seq in (f"{E}[>4;0m", f"{E}[20l", f"{E}[?1l", f"{E}>", f"{E}[?1049l", f"{E}[?25h"):
    if seq not in cf.RESET:
        failed += 1
        print(f"FAIL RESET lacks {seq!r}")

print("console-filter: ok" if not failed else f"console-filter: {failed} failed")
sys.exit(1 if failed else 0)

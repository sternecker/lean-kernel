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


def main():
    f = Filter()
    dec = codecs.getincrementaldecoder("utf-8")("replace")
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

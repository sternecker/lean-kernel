#!/usr/bin/env python3
"""No invisible or bidirectional-control characters in the repo's text files:
python3 -I tests/invisible-chars-test.py

Unicode format characters (category Cf: bidi overrides and isolates, zero-width spaces and joiners, the
BOM, ...) and the soft hyphen render as nothing, or reorder the text around them, so a reviewer reading a
diff can't see them ("Trojan Source", CVE-2021-42574). Code that needs one (the console filter's lists,
their tests) writes it as an escape, \\u202e, which reads as what it is. Files that aren't UTF-8 text
(the PDF) are skipped."""
import os
import sys
import unicodedata

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SKIP_DIRS = {".git", "work", "bin", "out", "__pycache__"}
bad = 0
for d, dirs, files in os.walk(root):
    dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith("out-"))
    for f in sorted(files):
        p = os.path.join(d, f)
        try:
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for c in line:
                if unicodedata.category(c) == "Cf" or c == "\u00ad":
                    print(f"FAIL {os.path.relpath(p, root)}:{n}: U+{ord(c):04X} {unicodedata.name(c, '?')}"
                          " written literally; use an escape")
                    bad += 1
                    break
print("invisible-chars:", "FAIL" if bad else "ok", f"({bad} lines)")
sys.exit(1 if bad else 0)

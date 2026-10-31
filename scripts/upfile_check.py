#!/usr/bin/env python3
"""tools/upfile.c (goose-http's reads of a -T file) without Goose:
test/native/upfile_drive.c compiled with it: a file of 300,000 bytes with
CR, LF and ^Z in it read in pieces, its size, read again after a rewind,
a missing file, and standard input from a file (its size) and from a
pipe (none), read in binary mode.

    python3 scripts/upfile_check.py [--cc CC]       # POSIX: cc, -Wall -Wextra -Werror
    python3 scripts/upfile_check.py --msvc          # Windows: cl /W4 /WX, from a vcvars64 shell
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--msvc", action="store_true")
    args = ap.parse_args()
    src = [os.path.join(ROOT, "test", "native", "upfile_drive.c"), os.path.join(ROOT, "tools", "upfile.c")]
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "drive.exe" if args.msvc else "drive")
        if args.msvc:
            cmd = ["cl", "/nologo", "/W4", "/WX", "/O2", *src, "/Fe:" + exe, "/Fo:" + tmp + "\\"]
        else:
            cmd = [args.cc, "-O2", "-Wall", "-Wextra", "-Werror", "-o", exe, *src]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("compile failed:\n" + p.stdout + p.stderr)
        data = b"a\r\nb\n"
        inp = os.path.join(tmp, "in.bin")
        with open(inp, "wb") as f:
            f.write(data)
        bad = 0
        with open(inp, "rb") as f:
            r1 = subprocess.run([exe, "5"], stdin=f, capture_output=True, text=True, cwd=tmp)
        r2 = subprocess.run([exe, "-1"], input=data, capture_output=True, cwd=tmp)
        for tag, r in (("stdin a file", r1), ("stdin a pipe", r2)):
            out = r.stdout if isinstance(r.stdout, str) else r.stdout.decode()
            print(f"-- {tag}\n{out.rstrip()}")
            bad += r.returncode != 0
        sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

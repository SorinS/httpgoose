#!/usr/bin/env python3
"""Run the http package's tests and examples.

Every test/*.goose runs under the in-process JIT at -O0 and -O2 and with
--debug (overflow, range and bounds checks); a test passes when it exits 0
and, if test/expected/<name>.txt exists, prints exactly that. The examples
run once. --native also builds and runs the tests with the C compiler.

    python3 scripts/run_tests.py [--goose PATH] [--native] [--update] [-k NAME]

The compiler is --goose, else $GOOSE, else `goose` on PATH, else
../goose.git/build/goose beside this repository.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
EXAMPLE_ARGS = {}


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def strip_notes(text):
    # The compiler's progress lines go to stderr, but keep stdout clean too.
    return "".join(l for l in text.splitlines(True)
                   if not l.startswith(("parsed ok", "typechecked ok", "bce:")))


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, strip_notes(p.stdout), p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--native", action="store_true")
    ap.add_argument("--update", action="store_true", help="rewrite expected outputs")
    ap.add_argument("-k", help="only files whose name contains this")
    args = ap.parse_args()
    goose = find_goose(args.goose)

    test_dir = os.path.join(ROOT, "test")
    tests = sorted(f for f in os.listdir(test_dir) if f.endswith(".goose"))
    ex_dir = os.path.join(ROOT, "examples")
    examples = sorted(f for f in os.listdir(ex_dir) if f.endswith(".goose")) if os.path.isdir(ex_dir) else []
    if args.k:
        tests = [t for t in tests if args.k in t]
        examples = [e for e in examples if args.k in e]
    failed = []
    passed = 0

    def check(label, rc, out, err, expected_path):
        nonlocal passed
        ok = rc == 0
        if ok and expected_path and os.path.exists(expected_path):
            ok = open(expected_path).read() == out
            if not ok:
                err = f"output differs from {os.path.relpath(expected_path, ROOT)}:\n{out}"
        print(("ok    " if ok else "FAIL  ") + label)
        if ok:
            passed += 1
        else:
            failed.append(label)
            print("      " + (err or out).strip().replace("\n", "\n      "))

    for t in tests:
        name = t[:-6]
        expected = os.path.join(test_dir, "expected", name + ".txt")
        for flags in (["-O0"], ["-O2"], ["--debug"]):
            rc, out, err = run([goose, *flags, t], test_dir)
            if args.update and flags == ["-O0"] and rc == 0:
                os.makedirs(os.path.dirname(expected), exist_ok=True)
                with open(expected, "w") as f:
                    f.write(out)
            check(f"{t} {' '.join(flags)}", rc, out, err, expected)
        if args.native:
            with tempfile.TemporaryDirectory() as tmp:
                exe = os.path.join(tmp, name)
                rc, out, err = run([goose, "build", "-o", exe, t], test_dir)
                if rc == 0:
                    rc, out, err = run([exe], test_dir)
                check(f"{t} native", rc, out, err, expected)

    for e in examples:
        rc, out, err = run([goose, e, "--", *EXAMPLE_ARGS.get(e[:-6], [])], os.path.join(ROOT, "examples"))
        check(f"examples/{e}", rc, out, err, None)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

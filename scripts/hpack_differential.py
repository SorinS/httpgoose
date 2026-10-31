#!/usr/bin/env python3
"""HPACK, this package's against golang.org/x/net/http2/hpack.

tools/hpackoracle (Go) makes connections of header blocks: random header
lists through Go's encoder, with changes of the table size between them,
and some blocks changed at random (a bit flipped, cut short, bytes put
in). Both decoders read every block, and the fields or the refusal must be
the same. Then every list Go decoded is encoded by this package's encoder
(tools/hpackverdict.goose), with the same table sizes, and Go's decoder
must read each block back to the same fields.

    python3 scripts/hpack_differential.py [--goose PATH] [--seed N] [--conns N] [-v]

Two kinds of difference are Go's, counted apart:

  size-update-late  a size update after a field, which RFC 7541 §4.2 puts
                    at the start of a block only; Go takes it while its
                    table is empty
  two-size-updates  two size updates at the start of a block (the
                    smallest size since the last block, then the size now,
                    as §4.2 has an encoder send them, and as Go's encoder
                    does): Go's decoder refuses the second while its table
                    is not empty, taking the first for a field

Exit status 1 if any other case differs.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def read_int(b, p, n):
    mask = (1 << n) - 1
    v = b[p] & mask
    p += 1
    if v < mask:
        return v, p
    shift = 0
    while p < len(b):
        c = b[p]
        p += 1
        v += (c & 0x7f) << shift
        shift += 7
        if not c & 0x80:
            return v, p
    return None, None


def late_size_update(block):
    """Whether the block has a size update after a field (walking it the
    way a decoder does, up to where it stops making sense)."""
    p, seen = 0, False
    while p < len(block):
        c = block[p]
        if c & 0x80:
            _, p = read_int(block, p, 7)
        elif c & 0xe0 == 0x20:
            if seen:
                return True
            _, p = read_int(block, p, 5)
            if p is None:
                return False
            continue
        else:
            idx, p = read_int(block, p, 6 if c & 0xc0 == 0x40 else 4)
            if p is None:
                return False
            for _ in range(1 if idx else 2):
                if p >= len(block):
                    return False
                n, p = read_int(block, p, 7)
                if p is None:
                    return False
                p += n
        if p is None:
            return False
        seen = True
    return False


def two_updates_first(block):
    """Whether the block starts with two size updates."""
    p = 0
    for _ in range(2):
        if p >= len(block) or block[p] & 0xe0 != 0x20:
            return False
        _, p = read_int(block, p, 5)
        if p is None:
            return False
    return True


def blocks(lines):
    """(block hex, the lines after it) for each block, in order."""
    out, cur = [], None
    for l in lines:
        if l.startswith("block "):
            cur = [l[6:], []]
            out.append(cur)
        elif cur is not None and (l.startswith("ok") or l.startswith("error") or l.startswith("field")):
            cur[1].append(l)
        elif l.startswith("conn"):
            cur = None
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--conns", type=int, default=3000)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    tmp = tempfile.mkdtemp()
    try:
        env = dict(os.environ, GOFLAGS="-mod=mod", GOPROXY="off", GOSUMDB="off")
        oracle = os.path.join(tmp, "hpackoracle")
        subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "hpackoracle"), env=env, check=True)
        verdict = os.path.join(tmp, "hpackverdict")
        p = subprocess.run([goose, "build", "-O2", "-o", verdict, os.path.join(ROOT, "tools", "hpackverdict.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        cases = os.path.join(tmp, "cases.txt")
        with open(cases, "w") as f:
            subprocess.run([oracle, "gen", "-seed", str(args.seed), "-n", str(args.conns)], stdout=f, check=True)
        go = blocks(open(cases).read().splitlines())
        ours = blocks(subprocess.run([verdict, "decode", cases], capture_output=True, text=True, check=True).stdout.splitlines())
        differ, late, two, refused = 0, 0, 0, 0
        for (gb, gr), (ob, orr) in zip(go, ours):
            if gb != ob:
                sys.exit("the block lists are out of step")
            if gr and gr[0] == "error":
                refused += 1
            if gr == orr:
                continue
            raw = bytes.fromhex(gb.replace("-", ""))
            if gr and orr and gr[0].startswith("ok") and orr[0] == "error" and late_size_update(raw):
                late += 1
                continue
            if gr and orr and gr[0] == "error" and orr[0] == "ok" and two_updates_first(raw):
                two += 1
                # Go's decoder is out of step from here: the connection's
                # later blocks are not compared.
                continue
            differ += 1
            if args.v or differ <= 5:
                print(f"differ: block {gb if args.v else gb[:120]}\n  go:    {gr[:3]}\n  goose: {orr[:3]}")
        if len(go) != len(ours):
            print(f"differ: {len(go)} blocks from Go, {len(ours)} decoded here")
            differ += 1
        print(f"decoding: {len(go)} blocks ({refused} refused by Go), {differ} differ, {late} size-update-late, "
              f"{two} two-size-updates")
        # Encoding: every list again, through Go's decoder.
        enc = subprocess.run([verdict, "encode", cases], capture_output=True, text=True, check=True).stdout
        chk = subprocess.run([oracle, "check"], input=enc, capture_output=True, text=True, check=True).stdout.splitlines()
        bad = [l for l in chk if l != "ok"]
        for l in bad[:5]:
            print("encoding:", l)
        print(f"encoding: {len(chk)} blocks, {len(bad)} that Go does not read back")
        sys.exit(1 if differ or bad else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()

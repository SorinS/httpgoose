#!/usr/bin/env python3
"""gzip and deflate decoding, http.flate against Python's zlib.

Makes streams with zlib (every level, the strategies that give stored,
fixed-Huffman, Huffman-only, RLE and dynamic blocks, many small flushes),
of data that is random, repetitive, text-like and empty; wraps them as
gzip (with the optional FEXTRA, FNAME, FCOMMENT and FHCRC header fields,
several members in a row), zlib, and raw DEFLATE; and corrupts some (a
flipped bit, a cut end, a wrong CRC-32, Adler-32 or length, trailing
bytes). tools/flateverdict.goose decodes each fed in chunks of 1 byte up;
its result must be zlib's: the same bytes, or an error where zlib has one.

    python3 scripts/flate_differential.py [--goose PATH] [--seed N] [--count N] [-v]
"""

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def payload(rng):
    kind = rng.randrange(5)
    n = rng.choice([0, 1, 2, 10, 100, 1000, 5000, 40000, 70000, 140000])
    if kind == 0:
        return rng.randbytes(n)
    if kind == 1:
        return bytes([rng.randrange(4)]) * n
    if kind == 2:
        words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog", b"\n", b"<div>", b"</div>"]
        out = b" ".join(rng.choice(words) for _ in range(n // 4 + 1))
        return out[:n]
    if kind == 3:
        unit = rng.randbytes(rng.randrange(1, 300))
        return (unit * (n // len(unit) + 1))[:n]
    return bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))


def raw_deflate(rng, data):
    level = rng.choice([0, 1, 6, 9, -1])
    strategy = rng.choice([zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FILTERED])
    c = zlib.compressobj(level, zlib.DEFLATED, -15, rng.choice([1, 8, 9]), strategy)
    out = b""
    pos = 0
    while pos < len(data):
        step = rng.choice([len(data), 1, 7, 1000, 20000])
        out += c.compress(data[pos:pos + step])
        if rng.random() < 0.3:
            out += c.flush(rng.choice([zlib.Z_SYNC_FLUSH, zlib.Z_FULL_FLUSH]))
        pos += step
    return out + c.flush()


def gzip_member(rng, data):
    flg = 0
    extra = b""
    if rng.random() < 0.3:
        flg |= 4
        x = rng.randbytes(rng.randrange(0, 40))
        extra += struct.pack("<H", len(x)) + x
    if rng.random() < 0.3:
        flg |= 8
        extra += b"name.txt\x00"
    if rng.random() < 0.3:
        flg |= 16
        extra += b"a comment\x00"
    head = b"\x1f\x8b\x08" + bytes([flg | (2 if rng.random() < 0.3 else 0)]) + b"\x00\x00\x00\x00\x00\x03" + extra
    if head[3] & 2:
        head += struct.pack("<H", zlib.crc32(head) & 0xffff)
    return head + raw_deflate(rng, data) + struct.pack("<II", zlib.crc32(data), len(data) & 0xffffffff)


def zlib_stream(rng, data):
    level = rng.choice([0, 1, 6, 9])
    return zlib.compress(data, level) if rng.random() < 0.5 else (
        b"\x78\x9c" + raw_deflate(rng, data) + struct.pack(">I", zlib.adler32(data)))


def expected(fmt, stream):
    """zlib's result: (decoded bytes) or None for an error."""
    try:
        if fmt == "gzip":
            out = b""
            rest = stream
            first = True
            while first or rest:
                if not first and rest[:1] != b"\x1f":
                    return None
                d = zlib.decompressobj(31)
                out += d.decompress(rest)
                if not d.eof:
                    return None
                rest = d.unused_data
                first = False
            return out
        if stream[:2] and len(stream) >= 2 and (stream[0] & 15) == 8 and (stream[0] >> 4) <= 7 and \
                (stream[0] * 256 + stream[1]) % 31 == 0:
            d = zlib.decompressobj(15)
        else:
            d = zlib.decompressobj(-15)
        out = d.decompress(stream)
        if not d.eof or d.unused_data:
            return None
        return out
    except zlib.error:
        return None


def corrupt(rng, s):
    k = rng.randrange(5)
    if not s:
        return s
    if k == 0:
        i = rng.randrange(len(s))
        return s[:i] + bytes([s[i] ^ (1 << rng.randrange(8))]) + s[i + 1:]
    if k == 1:
        return s[:rng.randrange(len(s))]
    if k == 2:
        return s[:-8] + bytes([s[-8] ^ 1]) + s[-7:] if len(s) > 8 else s[:-1]
    if k == 3:
        return s[:-1] + bytes([s[-1] ^ 0x80])
    return s + rng.choice([b"\x00", b"junk", b"\x1f\x8b"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=600)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    cases = []
    for i in range(args.count):
        data = payload(rng)
        fmt = rng.choice(["gzip", "gzip", "deflate", "deflate-raw"])
        if fmt == "gzip":
            s = gzip_member(rng, data)
            if rng.random() < 0.2:
                s += gzip_member(rng, payload(rng))
        elif fmt == "deflate":
            s = zlib_stream(rng, data)
        else:
            s = raw_deflate(rng, data)
        bad = rng.random() < 0.25
        if bad:
            s = corrupt(rng, s)
        name = "gzip" if fmt == "gzip" else "deflate"
        chunk = rng.choice([1, 2, 3, 7, 64, 1000, 1 << 20])
        cases.append((name, chunk, s, bad))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cases.txt")
        with open(path, "w") as f:
            for name, chunk, s, _ in cases:
                f.write(f"{name} {chunk} {s.hex() or '-'}\n")
        p = subprocess.run([goose, "-O2", "tools/flateverdict.goose", "--", path], cwd=ROOT, capture_output=True,
                           text=True)
        if p.returncode != 0:
            sys.exit("flateverdict failed:\n" + p.stderr)
        ours = p.stdout.splitlines()
    if len(ours) != len(cases):
        sys.exit(f"{len(ours)} results for {len(cases)} cases")
    diffs = 0
    errors = 0
    for (name, chunk, s, bad), got in zip(cases, ours):
        want = expected(name, s)
        if want is None:
            errors += 1
            ok = not got.startswith("ok")
        else:
            ok = got == f"ok {len(want)} {zlib.crc32(want):08x}"
        if not ok:
            diffs += 1
            if args.v or diffs <= 20:
                print(f"DIFF {name} chunk={chunk} bad={bad} len={len(s)}: ours {got!r}, zlib "
                      f"{'error' if want is None else len(want)}")
    print(f"{len(cases)} streams ({errors} zlib refuses), {diffs} differ")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()

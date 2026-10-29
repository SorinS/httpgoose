#!/usr/bin/env python3
"""HTTP/1.1 request parsing, this package's against Go's net/http server.

Generates requests that vary what request smuggling turns on (the request
line, Host, Content-Length, Transfer-Encoding, line endings, whitespace,
duplicates, chunked bodies), gives the same bytes to tools/h1verdict.goose
and to tools/h1oracle (Go's http.Server on 127.0.0.1), and sorts the
differences:

  framing  both took the request but read its body differently: what
           smuggling needs, so every one is an error to fix
  lenient  this package took a request Go refused: each is examined
  strict   this package refused a request Go took: each needs a reason

    python3 scripts/h1_differential.py [--goose PATH] [--go PATH] [--seed N] [--random N] [-v]

Exit status 1 if there is a framing difference.
"""

import argparse
import collections
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

EOLS = [b"\r\n", b"\n", b"\r", b"\r\r\n", b"\n\r"]
TE_NAMES = [b"Transfer-Encoding", b"transfer-encoding", b"Transfer-Encoding ", b" Transfer-Encoding",
            b"Transfer_Encoding", b"Transfer-Encoding\t", b"TRANSFER-ENCODING", b"Transfer-Encodings"]
TE_VALUES = [b"chunked", b" chunked", b"chunked ", b"Chunked", b"chunked,", b",chunked", b"chunked, chunked",
             b"gzip, chunked", b"chunked, gzip", b"identity", b"identity, chunked", b"\x0bchunked", b"\"chunked\"",
             b"chunked;x=1", b"xchunked", b"chunk", b"", b"\tchunked", b"chunked\x00", b"cHuNkEd"]
CL_NAMES = [b"Content-Length", b"content-length", b"Content-Length ", b" Content-Length", b"Content_Length",
            b"CONTENT-LENGTH"]
CL_VALUES = [b"5", b"05", b"+5", b"-5", b"5 ", b" 5", b"5,5", b"5, 5", b"5, 6", b"0x5", b"", b"5.0",
             b"99999999999999999999", b"5\x00", b"0", b"1e1", b"\t5", b"5\t", b"00000000000000000005"]
LINES = [b"GET / HTTP/1.1", b"POST / HTTP/1.1", b"POST / HTTP/1.0", b"POST /x HTTP/1.2", b"GET  / HTTP/1.1",
         b"GET / HTTP/1.1 ", b"GET\t/ HTTP/1.1", b"GET / http/1.1", b"GET / HTTP/2.0", b"GET /a b HTTP/1.1",
         b"GET http://a/x HTTP/1.1", b"OPTIONS * HTTP/1.1", b"GET * HTTP/1.1", b"CONNECT a:443 HTTP/1.1",
         b"GET a/b HTTP/1.1", b"GET / HTTP/1.10", b"G\x00T / HTTP/1.1", b"GET /\x7f HTTP/1.1"]
HOSTS = [b"Host: a", b"Host: a:80", b"Host: [::1]:80", b"Host:", b"Host: a b", b"Host: a/b", b"Host: u@a",
         b"Host: a\x00", None, b"Host: a\r\nHost: b", b"Host: a\r\nHost: a", b"host: a", b"Host : a", b" Host: a"]
OTHER = [b"X-A: b", b"X-A:b", b"X-A:  b  ", b"X-A: b\r\n c", b"X-A: \x01", b"X-A: \xc3\xa9", b": b", b"X-A",
         b"X\"A: b", b"X-A: b\x7f", b"Connection: close", b"Expect: 100-continue"]
BODIES = [b"", b"hello", b"5\r\nhello\r\n0\r\n\r\n", b"5;e=1\r\nhello\r\n0\r\n\r\n", b"5\nhello\n0\n\n",
          b"5\r\nhello\r\n0\r\nX: y\r\n\r\n", b"0x5\r\nhello\r\n0\r\n\r\n", b"5 \r\nhello\r\n0\r\n\r\n",
          b"5\r\nhelloX\r\n0\r\n\r\n", b"000005\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\n",
          b"hellohello", b"5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"]


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def request(line, host, fields, body, eol=b"\r\n"):
    parts = [line]
    if host is not None:
        parts.append(host)
    parts += fields
    return eol.join(parts) + eol + eol + body


def cases(rng, extra):
    out = []
    host = b"Host: a"
    post = b"POST / HTTP/1.1"
    for line in LINES:
        out.append(request(line, host, [], b""))
    for h in HOSTS:
        out.append(request(b"GET / HTTP/1.1", h, [], b""))
        out.append(request(b"GET / HTTP/1.0", h, [], b""))
    for f in OTHER:
        out.append(request(b"GET / HTTP/1.1", host, [f], b""))
    for eol in EOLS:
        out.append(request(b"GET / HTTP/1.1", host, [b"X: y"], b"", eol))
        out.append(b"GET / HTTP/1.1\r\nHost: a" + eol + b"\r\n")
    for n in TE_NAMES:
        for v in TE_VALUES:
            for body in (b"5\r\nhello\r\n0\r\n\r\n", b"hello"):
                out.append(request(post, host, [n + b": " + v], body))
    for n in CL_NAMES:
        for v in CL_VALUES:
            out.append(request(post, host, [n + b": " + v], b"hellohello"))
    for v in CL_VALUES:
        out.append(request(post, host, [b"Content-Length: 5", b"Content-Length: " + v], b"hellohello"))
    for body in BODIES:
        out.append(request(post, host, [b"Transfer-Encoding: chunked"], body))
        out.append(request(post, host, [b"Content-Length: 5"], body))
    for tv in TE_VALUES[:8]:
        for cv in CL_VALUES[:6]:
            out.append(request(post, host, [b"Transfer-Encoding: " + tv, b"Content-Length: " + cv], b"5\r\nhello\r\n0\r\n\r\n"))
            out.append(request(post, host, [b"Content-Length: " + cv, b"Transfer-Encoding: " + tv], b"5\r\nhello\r\n0\r\n\r\n"))
    for _ in range(extra):
        line = rng.choice(LINES)
        fields = []
        for _ in range(rng.randrange(0, 4)):
            pick = rng.randrange(3)
            if pick == 0:
                fields.append(rng.choice(TE_NAMES) + b":" + rng.choice([b" ", b"", b"\t"]) + rng.choice(TE_VALUES))
            elif pick == 1:
                fields.append(rng.choice(CL_NAMES) + b":" + rng.choice([b" ", b""]) + rng.choice(CL_VALUES))
            else:
                fields.append(rng.choice(OTHER))
        rng.shuffle(fields)
        out.append(request(line, rng.choice(HOSTS), fields, rng.choice(BODIES), rng.choice(EOLS[:2] * 4 + EOLS)))
    seen = set()
    unique = []
    for c in out:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def classify(ours, go):
    def accepted(v):
        return v.startswith("ok ")
    if ours == go:
        return None
    if accepted(ours) and accepted(go):
        return "framing"
    if accepted(ours):
        return "lenient"
    if accepted(go):
        return "strict"
    return "rejected-differently"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--go", default=shutil.which("go") or "go")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--random", type=int, default=3000, help="random combinations beyond the systematic ones")
    ap.add_argument("-v", action="store_true", help="print every difference")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    reqs = cases(rng, args.random)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cases.txt")
        with open(path, "w") as f:
            for r in reqs:
                f.write(r.hex() + "\n")
        oracle = os.path.join(tmp, "h1oracle")
        env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod")
        subprocess.run([args.go, "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "h1oracle"), env=env, check=True)
        go = subprocess.run([oracle, "-cases", path], capture_output=True, text=True, check=True).stdout.splitlines()
        ours = subprocess.run([goose, os.path.join(ROOT, "tools", "h1verdict.goose"), "--", path],
                              capture_output=True, text=True, check=True).stdout.splitlines()
    if len(go) != len(reqs) or len(ours) != len(reqs):
        sys.exit(f"verdict counts differ: {len(reqs)} cases, {len(ours)} ours, {len(go)} Go's")
    groups = collections.defaultdict(list)
    same = 0
    for r, o, g in zip(reqs, ours, go):
        o, g = o.strip(), g.strip()
        # Go's server answers OPTIONS * itself (200, no handler): the body
        # it would have read is not known, so a 200 counts as taking it.
        if r.startswith(b"OPTIONS * ") and g == "status 200" and o.startswith("ok "):
            g = o
        if g == "dialerr":
            sys.exit("h1oracle could not connect to its own server")
        k = classify(o, g)
        if k is None:
            same += 1
        else:
            groups[k].append((r, o, g))
    print(f"{len(reqs)} requests: {same} the same", end="")
    for k in ("framing", "lenient", "strict", "rejected-differently"):
        print(f", {len(groups[k])} {k}", end="")
    print()
    for k in ("framing", "lenient", "strict", "rejected-differently"):
        items = groups[k]
        if not items:
            continue
        print(f"\n== {k}")
        shown = items if args.v or k in ("framing", "lenient") else items[:40]
        for r, o, g in shown:
            print(f"  {r!r}\n      ours: {o[:60]}   go: {g[:60]}")
        if len(shown) < len(items):
            print(f"  ... {len(items) - len(shown)} more (-v)")
    sys.exit(1 if groups["framing"] else 0)


if __name__ == "__main__":
    main()

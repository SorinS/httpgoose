#!/usr/bin/env python3
"""URL parsing and resolution, this package's against Go's net/url.

Takes every string literal of Go's own net/url tests, RFC 3986 §5.4's
examples and generated URLs (schemes, userinfo, hosts and IPv6 literals,
ports, paths with dot segments and escapes, queries, fragments, and bytes
that should be refused), parses each with tools/urlverdict.goose and with
tools/urloracle (Go's url.Parse), resolves it against bases (Go's
URL.Parse), and compares every part: scheme, opaque part, user, password,
host name, port, decoded path, query and decoded fragment.

    python3 scripts/url_differential.py [--goose PATH] [--go PATH] [--seed N] [--random N] [-v]

Two kinds of difference are Go's, where this package follows RFC 3986
§5.2.2 and they are counted apart:

  empty-authority  a reference "//" with an empty authority ("//?q"): Go
                   cannot tell it from no authority and keeps the base's
                   host; the RFC's result has none
  empty-query      a base with an empty query ("x?") and a reference with
                   no path or query: Go drops the "?", the RFC keeps it

Exit status 1 if any other case differs.
"""

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

RFC_BASE = "http://a/b/c/d;p?q"
RFC_REFS = ["g:h", "g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s", "g#s", "g?y#s", ";x", "g;x", "g;x?y#s", "",
            ".", "./", "..", "../", "../g", "../..", "../../", "../../g", "../../../g", "../../../../g", "/./g",
            "/../g", "g.", ".g", "g..", "..g", "./../g", "./g/.", "g/./h", "g/../h", "g;x=1/./y", "g;x=1/../y",
            "g?y/./x", "g?y/../x", "g#s/./x", "g#s/../x", "http:g"]

SCHEMES = ["http", "https", "HTTP", "HtTpS", "ftp", "mailto", "h+t-t.p", "1http", "+x", "", "ws", "x"]
USERS = ["", "u@", "user:pass@", "u%40x:p%3Ap@", "u:@", ":p@", "u:p@q@", "u%zz@", "u p@", "u/x@", "a@b@",
         "é@", "u:p:q@", "%41:%42@"]
HOSTS = ["a", "example.com", "EXAMPLE.com", "127.0.0.1", "[::1]", "[::1%25en0]", "[fe80::1%25%65n0]",
         "[1.2.3.4]", "[::ffff:1.2.3.4]", "[1:2:3:4:5:6:7:8]", "[1:2:3:4:5:6:7:8:9]", "[::]", "[:::]",
         "[12345::]", "[1::2::3]", "[::1", "::1]", "a[b]", "", "a b", "a%20b", "a%c3%a9", "é.com", "a<b",
         "a\"b", "a{b", "a|b", "a^b", "a_b", "a~b", "a%2eb", "[::1]x", "[0:0:0:0:0:0:0:1]", "[::1.2.3.4]",
         "[1::1.2.3.4]", "[1:2:3:4:5:6:1.2.3.4]", "[1:2:3:4:5:6:7:1.2.3.4]", "[01.2.3.4]", "[::%25]",
         "[fe80::1%25]", "[fe80::1%25en%200]", "[fe80::1%en0]"]
PORTS = ["", ":", ":80", ":8080", ":0", ":65536", ":99999999999", ":x", ":8a", ":-1", ":80:90", ":+1"]
PATHS = ["", "/", "/a", "/a/b/c", "/a/./b", "/a/../b", "/../a", "/./", "/a/b/..", "/a/b/.", "/%2e%2e/a",
         "/a%2Fb", "/a b", "/a%zz", "/a%2", "/%", "/é", "/a?b", "/a;b=c", "//x", "///x", "/a//b",
         "/~u/", "/a:b", "/[x]", "/{x}", "/a|b", "/a\"b", "/a<b>", "/a\\b", "/a^b", "/a`b"]
QUERIES = ["", "?", "?q", "?a=1&b=2", "?a b", "?%zz", "??", "?a?b", "?a=%20", "?a+b", "?é", "?a#"]
FRAGS = ["", "#", "#f", "#a b", "#%zz", "#%41", "#a#b", "#é", "#/a?b"]
BYTES = ["\x00", "\x01", "\t", "\n", "\x7f", " ", "%", "#", "?", "@", ":", "[", "]", "ÿ"]
BASES = [RFC_BASE, "http://a/b/c/d;p?q#f", "https://u:p@h:1/x/y", "http://h", "http://h/", "http://[::1]:8/a/b",
         "mailto:x@y", "http:/a/b", "foo:bar/baz", "http://h/a/b/", "http://h?q", "//h/a", "/a/b", "a/b",
         "http://h/%41/b%2fc/d"]


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def go_literals(go):
    """The string literals of Go's net/url tests."""
    goroot = subprocess.run([go, "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
    src = open(os.path.join(goroot, "src", "net", "url", "url_test.go"), encoding="utf-8").read()
    out = []
    for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', src):
        raw = m.group(1)
        try:
            s = bytes(raw, "utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if any(c in s for c in ":/?#@%") and len(s) < 300:
            out.append(s)
    for m in re.finditer(r"`([^`]*)`", src):
        if any(c in m.group(1) for c in ":/?#@%") and len(m.group(1)) < 300:
            out.append(m.group(1))
    return sorted(set(out))


def generated(rng, n):
    out = []
    for _ in range(n):
        s = rng.choice(SCHEMES)
        u = s + ":" if s else ""
        if rng.random() < 0.85:
            u += "//" + rng.choice(USERS) + rng.choice(HOSTS) + rng.choice(PORTS)
        u += rng.choice(PATHS) + rng.choice(QUERIES) + rng.choice(FRAGS)
        if rng.random() < 0.1:
            i = rng.randrange(len(u) + 1)
            u = u[:i] + rng.choice(BYTES) + u[i:]
        out.append(u)
    return out


def relative(rng, n):
    out = []
    for _ in range(n):
        u = ""
        if rng.random() < 0.2:
            u = "//" + rng.choice(USERS) + rng.choice(HOSTS) + rng.choice(PORTS)
        segs = [rng.choice(["a", "b", ".", "..", "", "%2e", "x:y", "c;p", "%41"]) for _ in range(rng.randrange(4))]
        p = "/".join(segs)
        if rng.random() < 0.4:
            p = "/" + p
        u += p + rng.choice(QUERIES) + rng.choice(FRAGS)
        out.append(u)
    return out


def hexs(s):
    return s.encode("utf-8").hex() or "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--go", default=shutil.which("go") or "go")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--random", type=int, default=4000)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)

    lits = go_literals(args.go)
    gen = generated(rng, args.random)
    rel = relative(rng, args.random // 2)
    cases = [(RFC_BASE, r) for r in RFC_REFS]
    cases += [(None, s) for s in lits + gen]
    cases += [(rng.choice(BASES + gen[:50]), r) for r in rel + lits]
    cases += [(b, r) for b in BASES for r in RFC_REFS[:20]]

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cases.txt")
        with open(path, "w") as f:
            for b, r in cases:
                f.write(("-" if b is None else hexs(b)) + " " + hexs(r) + "\n")
        oracle = os.path.join(tmp, "urloracle")
        env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod")
        subprocess.run([args.go, "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "urloracle"),
                       env=env, check=True)
        go = subprocess.run([oracle, "-cases", path], capture_output=True, text=True, check=True).stdout.splitlines()
        ours = subprocess.run([goose, "tools/urlverdict.goose", "--", path], cwd=ROOT, capture_output=True,
                              text=True)
        if ours.returncode != 0:
            sys.exit("urlverdict failed:\n" + ours.stderr)
        ours = ours.stdout.splitlines()

    if len(go) != 2 * len(cases) or len(ours) != 2 * len(cases):
        sys.exit(f"line counts: cases {len(cases)}, go {len(go)}, ours {len(ours)}")
    diffs = 0
    known = {"empty-authority": 0, "empty-query": 0}
    for i, (b, r) in enumerate(cases):
        for k, what in ((0, "parse"), (1, "resolve")):
            g, o = go[2 * i + k], ours[2 * i + k]
            if g == o:
                continue
            kind = go_quirk(b, r) if k == 1 else None
            if kind:
                known[kind] += 1
                if not args.v:
                    continue
            else:
                diffs += 1
            if args.v or diffs <= 40:
                print(f"DIFF {what} {kind or ''} base={b!r} ref={r!r}\n  go:   {decode(g)}\n  ours: {decode(o)}")
    print(f"{len(cases)} cases ({len(lits)} from Go's tests), {2 * len(cases)} results, {diffs} differ; "
          f"Go's own: {known['empty-authority']} empty-authority, {known['empty-query']} empty-query")
    sys.exit(1 if diffs else 0)


def go_quirk(base, ref):
    """Which of Go's departures from RFC 3986 a resolution difference is."""
    if ref.startswith("//") and ref[2:3] in ("", "?", "#"):
        return "empty-authority"
    nofrag = ref.split("#", 1)[0]
    if nofrag == "" and base is not None and "?" in base.split("#", 1)[0] and base.split("#", 1)[0].split("?", 1)[1] == "":
        return "empty-query"
    return None


def decode(line):
    if not line.startswith("ok"):
        return line
    names = ["scheme", "opaque", "hasuser", "user", "haspass", "pass", "host", "port", "path", "hasq", "query", "frag"]
    vals = line.split()[1:]
    out = []
    for n, v in zip(names, vals):
        if v in ("0", "1") and n.startswith("has"):
            out.append(f"{n}={v}")
        elif v != "-":
            out.append(f"{n}={bytes.fromhex(v).decode('utf-8', 'replace')!r}")
    return "ok " + " ".join(out)


if __name__ == "__main__":
    main()

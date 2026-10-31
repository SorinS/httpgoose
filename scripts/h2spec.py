#!/usr/bin/env python3
"""h2spec (github.com/summerwind/h2spec), HTTP/2's conformance suite,
against goose-httpd: over TLS 1.3 (ALPN h2) and over TCP with prior
knowledge (h2c), on 127.0.0.1, with a 100 KB file as the path its tests
fetch (one of them needs a response longer than 100 bytes).

    python3 scripts/h2spec.py [--goose PATH] [--h2spec PATH] [-v]

Over TCP one test cannot pass and is counted apart: http2/3.5's
"invalid connection preface" sends "INVALID CONNECTION PREFACE\\r\\n\\r\\n",
which to a server taking HTTP/1.1 and HTTP/2 on one port is a request of
HTTP/1.1, answered with 400, not a GOAWAY. Exit status 1 if any other
test fails or is skipped.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
H2C_EXPECTED = {("http2/3.5", "Sends invalid connection preface")}


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def start(cmd):
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    line = p.stderr.readline()
    m = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
    if not m:
        p.kill()
        sys.exit("goose-httpd did not start: " + line)
    return p, int(m.group(1))


def run_h2spec(h2spec, port, tls, junit, verbose):
    cmd = [h2spec, "-h", "127.0.0.1", "-p", str(port), "-o", "5", "-P", "/big.bin", "-j", junit]
    if tls:
        cmd += ["-t", "-k"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if verbose:
        print(p.stdout)
    results = []
    for suite in ET.parse(junit).getroot():
        for case in suite:
            state = "passed"
            if case.find("failure") is not None or case.find("error") is not None:
                state = "failed"
            elif case.find("skipped") is not None:
                state = "skipped"
            results.append((case.get("package"), case.get("classname"), state))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--h2spec", default=shutil.which("h2spec") or "h2spec")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    tmp = tempfile.mkdtemp()
    procs = []
    bad = 0
    try:
        httpd = os.path.join(tmp, "goose-httpd")
        p = subprocess.run([goose, "build", "-o", httpd, os.path.join(ROOT, "tools", "httpd.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        www = os.path.join(tmp, "www")
        os.makedirs(www)
        with open(os.path.join(www, "index.html"), "w") as f:
            f.write("hello\n")
        with open(os.path.join(www, "big.bin"), "wb") as f:
            f.write(bytes((i * 7) % 251 for i in range(100000)))
        cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
        version = subprocess.run([args.h2spec, "--version"], capture_output=True, text=True).stdout.strip()
        print(f"h2spec {version}")
        for tag, opts, tls in (("tls 1.3", ["--cert", cert, "--key", key], True), ("h2c", [], False)):
            proc, port = start([httpd, "--root", www, "--port", "0", *opts])
            procs.append(proc)
            res = run_h2spec(args.h2spec, port, tls, os.path.join(tmp, "junit.xml"), args.v)
            counts = {"passed": 0, "failed": 0, "skipped": 0}
            expected = 0
            for pkg, name, state in res:
                if state != "passed" and not tls and (pkg, name) in H2C_EXPECTED:
                    expected += 1
                    continue
                counts[state] += 1
                if state != "passed":
                    print(f"  {tag}: {state}: {pkg} {name}")
            bad += counts["failed"] + counts["skipped"]
            extra = f", {expected} that cannot pass on a port shared with HTTP/1.1" if expected else ""
            print(f"{tag}: {len(res)} tests, {counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped{extra}")
            proc.kill()
    finally:
        for p in procs:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

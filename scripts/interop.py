#!/usr/bin/env python3
"""HTTP/1.1 interop on 127.0.0.1: goose-httpd against curl, Go's net/http
and Python's http.client, and goose-http against Go's net/http server and
a Python HTTP/1.0 server; each over TCP and TLS 1.2 and 1.3. Then
goose-http's policy (http.fetch): Go's table of redirect methods,
redirects across hosts, cookies (against curl's for the same exchanges),
Basic, Bearer and Digest credentials (a Python Digest server that curl
--digest is run against too), gzip, timeouts, and proxies: Go's forward
proxy (absolute-form, CONNECT, with and without credentials, over TLS
too), a SOCKS5 server, and the proxy environment.

    python3 scripts/interop.py [--goose PATH] [-k NAME]

Builds tools/httpd.goose, tools/http.goose and tools/gointerop, makes a
document root and a certificate (openssl), and prints "ok NAME" or
"FAIL NAME" a case, then the totals; exit status 1 if any failed. Every
server listens on 127.0.0.1 only.
"""

import argparse
import hashlib
import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
passed = 0
failed = []
only = None


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def check(name, ok, detail=""):
    global passed
    if only and only not in name:
        return
    if ok:
        passed += 1
        print("ok    " + name, flush=True)
    else:
        failed.append(name)
        if isinstance(detail, bytes):
            detail = repr(detail)
        print("FAIL  " + name + (": " + detail if detail else ""), flush=True)


def big():
    return bytes(((i * 7 + (i >> 8)) & 0xff) for i in range(1 << 20))


class Server:
    """A server process whose port it prints on a line matching `pattern`."""

    def __init__(self, cmd, pattern, stream="stderr"):
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        src = self.p.stderr if stream == "stderr" else self.p.stdout
        self.port = None
        self.log = []
        deadline = time.time() + 30
        while time.time() < deadline:
            line = src.readline()
            if not line:
                break
            self.log.append(line)
            m = re.search(pattern, line)
            if m:
                self.port = int(m.group(1))
                break
        if self.port is None:
            self.stop()
            sys.exit(f"{cmd[0]} did not start: {''.join(self.log)}")
        threading.Thread(target=lambda: [self.log.append(l) for l in src], daemon=True).start()

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def run(cmd, data=None, timeout=60):
    p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


# A curl with TLS 1.3: macOS's own is built on SecureTransport, which has
# none, so Homebrew's (OpenSSL) is taken where it is.
CURL = next((c for c in ("/opt/homebrew/opt/curl/bin/curl", "/usr/local/opt/curl/bin/curl") if os.path.exists(c)), "curl")


def curl_cases(port, tls, ca):
    scheme = "https" if tls else "http"
    host = "localhost" if tls else "127.0.0.1"
    base = f"{scheme}://{host}:{port}"
    tag = f"curl {tls or 'tcp'}"
    opts = ["-s", "--http1.1"]
    if tls:
        opts += ["--cacert", ca, "--tlsv" + tls, "--tls-max", tls]
    rc, out, err = run([CURL, *opts, base + "/index.html"])
    check(f"{tag}: GET", rc == 0 and out == b"hello from goose\n", err.decode()[:200])
    rc, out, err = run([CURL, *opts, base + "/big.bin"])
    check(f"{tag}: GET 1 MiB", rc == 0 and out == big())
    rc, out, err = run([CURL, *opts, "-I", base + "/big.bin"])
    check(f"{tag}: HEAD", rc == 0 and b"Content-Length: 1048576\r\n" in out and out.endswith(b"\r\n\r\n"))
    rc, out, err = run([CURL, *opts, "--data-binary", "@-", base + "/echo"], data=big())
    check(f"{tag}: POST 1 MiB (Expect: 100-continue)", rc == 0 and out == big())
    rc, out, err = run([CURL, *opts, "-H", "Transfer-Encoding: chunked", "--data-binary", "@-", base + "/echo"], data=b"x" * 70000)
    check(f"{tag}: POST chunked", rc == 0 and out == b"x" * 70000)
    rc, out, err = run([CURL, *opts, "-w", "%{http_code} %{num_connects}\n", "-o", "/dev/null", base + "/index.html",
                        "-o", "/dev/null", base + "/sub/a.txt", "-o", "/dev/null", base + "/missing"])
    lines = out.decode().split()
    check(f"{tag}: three requests, one connection", rc == 0 and lines == ["200", "1", "200", "0", "404", "0"], out.decode())
    rc, out, err = run([CURL, *opts, "--path-as-is", "-o", "/dev/null", "-w", "%{http_code}", base + "/../../etc/passwd"])
    check(f"{tag}: .. refused", out == b"400")
    rc, out, err = run([CURL, *opts, "--path-as-is", "-o", "/dev/null", "-w", "%{http_code}", base + "/%2e%2e/%2e%2e/etc/passwd"])
    check(f"{tag}: encoded .. refused", out == b"400")
    rc, out, err = run([CURL, *opts, "-o", "/dev/null", "-w", "%{http_code}", base + "/escape"])
    check(f"{tag}: a symbolic link out of the root refused", out == b"403")
    if tls:
        rc, out, err = run([CURL, *opts, "-v", "-o", "/dev/null", base + "/index.html"])
        e = err.decode()
        # curl 8 writes "ALPN: server accepted http/1.1", 7.x "ALPN, server
        # accepted to use http/1.1".
        alpn = re.search(r"ALPN[:,] server accepted (to use )?http/1\.1", e) is not None
        check(f"{tag}: TLS {tls} and ALPN http/1.1", f"TLSv{tls}" in e and alpn, e[-300:])


def python_cases(port, tls, ca):
    tag = f"python {tls or 'tcp'}"
    if tls:
        ctx = ssl.create_default_context(cafile=ca)
        v = ssl.TLSVersion.TLSv1_2 if tls == "1.2" else ssl.TLSVersion.TLSv1_3
        ctx.minimum_version = v
        ctx.maximum_version = v
        ctx.set_alpn_protocols(["http/1.1"])
        conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=30)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request("GET", "/index.html")
        r = conn.getresponse()
        b = r.read()
        check(f"{tag}: GET", r.status == 200 and b == b"hello from goose\n")
        sock = conn.sock
        conn.request("POST", "/echo", body=iter([b"a" * 1000, b"b" * 5000]), encode_chunked=True)
        r = conn.getresponse()
        b = r.read()
        check(f"{tag}: POST chunked", r.status == 200 and b == b"a" * 1000 + b"b" * 5000)
        conn.request("POST", "/echo", body=b"z" * 300000)
        r = conn.getresponse()
        b = r.read()
        check(f"{tag}: POST 300000 bytes", r.status == 200 and b == b"z" * 300000)
        check(f"{tag}: one connection for three", conn.sock is sock)
        if tls:
            check(f"{tag}: TLS {tls}", conn.sock.version() == ("TLSv1.2" if tls == "1.2" else "TLSv1.3")
                  and conn.sock.selected_alpn_protocol() == "http/1.1")
        conn.request("GET", "/index.html", headers={"Connection": "close"})
        r = conn.getresponse()
        r.read()
        check(f"{tag}: Connection: close answered and closed", r.status == 200 and r.getheader("Connection") == "close")
    except Exception as e:
        check(f"{tag}: exchange", False, repr(e))
    finally:
        conn.close()


def raw_cases(port):
    """Bytes a client library would not send, straight to goose-httpd."""
    def exchange(data):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        out = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
        s.close()
        return out
    out = exchange(b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\nGET /sub/a.txt HTTP/1.1\r\nHost: a\r\n\r\n")
    check("raw: two pipelined requests answered in order",
          out.count(b"HTTP/1.1 200 OK") == 2 and out.index(b"hello from goose") < out.index(b"sub\n"))
    out = exchange(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /index.html HTTP/1.1\r\nHost: a\r\n\r\n")
    check("raw: CL and TE together: 400 and closed", out.startswith(b"HTTP/1.1 400 ") and b"hello from goose" not in out, out[:80])
    out = exchange(b"GET / HTTP/1.1\nHost: a\n\n")
    check("raw: bare LF: 400", out.startswith(b"HTTP/1.1 400 "))
    out = exchange(b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 70000 + b"\r\n\r\n")
    check("raw: a head past 64 KiB: 431", out.startswith(b"HTTP/1.1 431 "))
    out = exchange(b"GET / HTTP/1.0\r\n\r\n")
    check("raw: HTTP/1.0 gets Connection: close", out.startswith(b"HTTP/1.1 200 ") and b"Connection: close\r\n" in out)


def goose_client_cases(gh, port, tls, ca, tag):
    scheme = "https" if tls else "http"
    host = "localhost" if tls else "127.0.0.1"
    base = f"{scheme}://{host}:{port}"
    opts = ["--cacert", ca, "--tls-max", tls] if tls else []
    rc, out, err = run([gh, *opts, base + "/hello"])
    check(f"{tag}: GET", rc == 0 and out == b"hello", err.decode()[:200])
    rc, out, err = run([gh, *opts, base + "/chunked"])
    check(f"{tag}: a chunked response", rc == 0 and out == b"one two three", err.decode()[:200])
    rc, out, err = run([gh, *opts, "-i", base + "/trailer"])
    check(f"{tag}: a response with a trailer", rc == 0 and out.endswith(b"body") and b"Transfer-Encoding: chunked" in out)
    rc, out, err = run([gh, *opts, base + "/big"])
    check(f"{tag}: GET 1 MiB", rc == 0 and out == big())
    rc, out, err = run([gh, *opts, "-d", "x" * 60000, base + "/echo"])
    check(f"{tag}: POST", rc == 0 and out == b"x" * 60000)
    rc, out, err = run([gh, *opts, "--chunked", "-d", "chunked body", base + "/echo"])
    check(f"{tag}: POST chunked", rc == 0 and out == b"chunked body")
    rc, out, err = run([gh, *opts, base + "/status/404"])
    check(f"{tag}: 404 exits 1", rc == 1)
    rc, out, err = run([gh, *opts, "-X", "HEAD", "-i", base + "/big"])
    # Go leaves out a HEAD response's length when the body would pass its
    # 2 KiB buffer: the head alone, then no body, is what is checked.
    check(f"{tag}: HEAD", rc == 0 and out.startswith(b"HTTP/1.1 200 OK\r\n") and out.endswith(b"\r\n\r\n"))
    rc, out, err = run([gh, *opts, base + "/hello", base + "/close", base + "/hello", base + "/chunked"])
    check(f"{tag}: four requests, a Connection: close among them", rc == 0 and out == b"helloclosinghelloone two three", out[:80])
    rc, out, err = run([gh, *opts, "-H", "Bad\r\nInjected: 1", base + "/hello"])
    check(f"{tag}: a header with CRLF refused", rc == 2)


DIGEST = r"""
import hashlib, http.server, re, secrets, sys
USER, PASSWORD, REALM = "Mufasa", "Circle of Life", "digest@test"
NONCE, OPAQUE = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
ALGS = {"md5": ("MD5", "md5"), "sha256": ("SHA-256", "sha256"), "sha256-sess": ("SHA-256-sess", "sha256"),
        "sha512-256": ("SHA-512-256", "sha512_256"), "authint": ("SHA-256", "sha256"), "userhash": ("SHA-256", "sha256")}
def H(alg, s):
    return hashlib.new(alg, s.encode()).hexdigest()
def params(v):
    out = {}
    for m in re.finditer(r'([A-Za-z0-9*-]+)\s*=\s*("((?:[^"\\]|\\.)*)"|[^,\s]+)', v):
        out[m.group(1).lower()] = re.sub(r'\\(.)', r'\1', m.group(3)) if m.group(3) is not None else m.group(2)
    return out
# What the server saw since /digest/stats was last read: 401s sent, and
# the nc values taken. Each 401 has a fresh nonce, and nc must grow with
# each request on a nonce (RFC 7616 §3.4). /digest/stale/* changes its
# nonce after every two requests it takes, answering a request on the old
# one with stale=true; /digest/dom/* names /digest/dom/ as its protection
# space (the domain param).
STATS = {"401": 0, "nc": []}
LAST_NC = {}
ISSUED = set()
STALE = {"gen": 0, "uses": 0}
class D(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.path == "/digest/stats":
            out = f"401 {STATS['401']} nc {','.join(STATS['nc'])}".encode()
            STATS["401"], STATS["nc"] = 0, []
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        kind = self.path.rsplit("/", 1)[-1]
        stale_kind = self.path.startswith("/digest/stale/")
        nonce = f"rotating-{STALE['gen']}" if stale_kind else None
        name, alg = ALGS.get(kind, ALGS["sha256"])
        qop = "auth-int" if kind == "authint" else "auth"
        a = self.headers.get("Authorization", "")
        ok = False
        if a.startswith("Digest "):
            p = params(a[7:])
            user = p.get("username")
            if kind == "userhash":
                ok_user = user == H(alg, USER + ":" + REALM) and p.get("userhash") == "true"
            else:
                ok_user = user == USER
            got_nonce = p.get("nonce", "")
            ha1 = H(alg, USER + ":" + REALM + ":" + PASSWORD)
            if name.endswith("-sess"):
                ha1 = H(alg, ha1 + ":" + got_nonce + ":" + p.get("cnonce", ""))
            a2 = self.command + ":" + p.get("uri", "")
            if qop == "auth-int":
                a2 += ":" + hashlib.new(alg, body).hexdigest()
            want = H(alg, ":".join([ha1, got_nonce, p.get("nc", ""), p.get("cnonce", ""), qop, H(alg, a2)]))
            ok = (ok_user and p.get("realm") == REALM and p.get("qop") == qop and
                  p.get("opaque") == OPAQUE and p.get("uri") == self.path and p.get("response") == want)
            try:
                nc = int(p.get("nc", ""), 16)
            except ValueError:
                nc = 0
            if ok and nc <= LAST_NC.get(got_nonce, 0):
                ok = False                      # a replayed nc
            if ok:
                LAST_NC[got_nonce] = nc
                STATS["nc"].append(str(nc))
            stale = ok and stale_kind and got_nonce != nonce and got_nonce.startswith("rotating-")
            if (stale_kind and got_nonce != nonce) or (not stale_kind and got_nonce not in ISSUED):
                ok = False
            if ok and stale_kind:
                STALE["uses"] += 1
                if STALE["uses"] == 2:
                    STALE["gen"], STALE["uses"] = STALE["gen"] + 1, 0
        else:
            stale = False
        if ok:
            out = b"digest ok"
            self.send_response(200)
        else:
            out = b"digest wanted"
            STATS["401"] += 1
            if nonce is None:
                nonce = secrets.token_hex(16)
                ISSUED.add(nonce)
            self.send_response(401)
            ch = f'Digest realm="{REALM}", qop="{qop}", algorithm={name}, nonce="{nonce}", opaque="{OPAQUE}"'
            if kind == "userhash":
                ch += ", userhash=true"
            if stale:
                ch += ", stale=true"
            if self.path.startswith("/digest/dom/"):
                ch += ', domain="/digest/dom/"'
            self.send_header("WWW-Authenticate", 'Basic realm="nope"')
            self.send_header("WWW-Authenticate", ch)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = handle_any
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), D)
print("listening", s.server_address[1], flush=True)
s.serve_forever()
"""


def fetch_cases(gh, gi, cert, g0, g13, dg, env_base):
    """goose-http's policy: redirects, cookies, credentials, gzip, proxies."""
    plain = f"http://127.0.0.1:{g0}"
    other = f"http://localhost:{g0}"
    tls = ["--cacert", cert]

    def gx(*a, env=None, timeout=60):
        p = subprocess.run([gh, *a], capture_output=True, timeout=timeout, env=env if env is not None else env_base)
        return p.returncode, p.stdout, p.stderr

    def field(out, name):
        m = re.search(rb"(?im)^" + name.encode() + rb": *(.*?)\r?$", out)
        return m.group(1).decode() if m else None

    # Go's TestClientRedirectTypes: (method, status) -> the next method; 307
    # and 308 send the body again, 301-303 drop it.
    for method in ["POST", "HEAD", "GET", "DELETE", "PUT", "MADEUPMETHOD"]:
        for status in [301, 302, 303, 307, 308]:
            want = method if status in (307, 308) or method in ("GET", "HEAD") else "GET"
            data = [] if method in ("GET", "HEAD") else ["-d", "payload"]
            rc, out, err = gx("-L", "-i", "-X", method, *data, f"{plain}/redir?status={status}&to=/inspect")
            body = "7" if status in (307, 308) and data else "0"
            ok = rc == 0 and field(out, "X-Method") == want and field(out, "X-Body") == body
            check(f"redirect: {method} then {status} -> {want}, body {body}", ok, out[:300] + err[:200])
    rc, out, err = gx("-L", f"{plain}/chain/5")
    check("redirect: a chain of 5 with -L", rc == 0 and out == b"chain end", out[:100])
    rc, out, err = gx("-L", "--max-redirs", "3", f"{plain}/chain/5")
    check("redirect: past --max-redirs fails", rc == 1 and b"too many redirects" in err, err[:200])
    rc, out, err = gx("-i", f"{plain}/chain/5")
    check("redirect: not followed without -L", rc == 0 and out.startswith(b"HTTP/1.1 302 Found") and b"Location: /chain/4" in out)
    hdrs = ["-H", "Authorization: Bearer x", "-H", "Cookie: a=1", "-H", "X-Keep: 1"]
    rc, out, err = gx("-L", *hdrs, f"{plain}/redir?status=302&to={other}/inspect")
    check("redirect: to another host drops Authorization and Cookie, keeps others, sends Referer",
          rc == 0 and b"host localhost:" in out and b"\nAuthorization:" not in out and b"\nCookie:" not in out and
          b"X-Keep: 1" in out and f"Referer: {plain}/redir?status=302&to={other}/inspect".encode() in out, out[:400])
    rc, out, err = gx("-L", *hdrs, f"{plain}/redir?status=302&to=/inspect")
    check("redirect: on one host keeps Authorization and Cookie",
          rc == 0 and b"Authorization: Bearer x" in out and b"Cookie: a=1" in out, out[:400])
    rc, out, err = gx("-L", *tls, f"https://localhost:{g13}/redir?status=302&to={plain}/inspect")
    check("redirect: no Referer from https to http", rc == 0 and b"method GET" in out and b"Referer" not in out, out[:400])
    rc, out, err = gx("-L", "-d", "x", f"{plain}/redir?status=303&to=/inspect")
    check("redirect: 303 drops Content-Type with the body", rc == 0 and b"Content-Type" not in out and b"method GET" in out, out[:300])

    # Cookies, and curl's jar for the same exchanges.
    sets = "c=a%3D1&c=b%3D2%3B%20Path%3D%2Fcookies&c=gone%3D1&c=gone%3Dx%3B%20Max-Age%3D0&c=q%3D%22v%20w%22"
    with tempfile.TemporaryDirectory() as d:
        gj, cj = os.path.join(d, "goose.txt"), os.path.join(d, "curl.txt")
        rc, out, err = gx("-c", gj, "-b", "", f"{plain}/setcookie?{sets}", f"{plain}/cookies", f"{plain}/inspect")
        crc, cout, cerr = run([CURL, "-s", "-c", cj, "-b", "", f"{plain}/setcookie?{sets}", f"{plain}/cookies",
                               f"{plain}/inspect"])
        # The same cookies; of two with one path, Go and RFC 6265 §5.4 send the
        # older first, curl the newer, so they are compared as sets.
        def sent(o):
            return sorted(o.split(b"method")[0][3:].split(b"; "))
        check("cookies: the ones curl sends", rc == 0 and sent(out) == sent(cout) and out.startswith(b"setb=2; "),
              f"goose {out[:120]!r} curl {cout[:120]!r}")
        def lines(path):
            return sorted(l for l in open(path).read().splitlines() if l and not l.startswith("# "))
        check("cookies: the jar file is curl's", rc == 0 and lines(gj) == lines(cj), f"{lines(gj)} vs {lines(cj)}")
        rc, out, err = gx("-b", cj, f"{plain}/cookies")
        check("cookies: curl's file read back", rc == 0 and out.startswith(b"b=2; ") and
              sorted(out.split(b"; ")) == [b"a=1", b"b=2", b'q="v w"'], out[:100])
        rc, out, err = gx("-c", gj, "-L", f"{plain}/setcookie?c=r%3D1&c=x%3Dy%3B%20Domain%3Dexample.com",
                          f"{plain}/cookies")
        check("cookies: a Domain of another site refused", rc == 0 and out == b"setr=1", out[:100])
        rc, out, err = gx("-b", "", "-L", f"{plain}/redir?status=302&to={other}/cookies")
        check("cookies: none sent to another host", rc == 0 and out == b"", out[:100])

    # Credentials.
    rc, out, err = gx("-u", "alice:secret", f"{plain}/basic")
    check("auth: Basic", rc == 0 and out == b"hello alice", out[:100])
    rc, out, err = gx("-u", "alice:wrong", f"{plain}/basic")
    check("auth: Basic refused exits 1", rc == 1 and out == b"who are you", out[:100])
    rc, out, err = gx("--anyauth", "-u", "alice:secret", f"{plain}/basic")
    check("auth: --anyauth answers Basic's 401", rc == 0 and out == b"hello alice", out[:100])
    rc, out, err = gx(f"http://alice:secret@127.0.0.1:{g0}/basic")
    check("auth: a URL's userinfo", rc == 0 and out == b"hello alice", out[:100])
    rc, out, err = gx("--oauth2-bearer", "tok123", f"{plain}/bearer")
    check("auth: Bearer", rc == 0 and out == b"token ok", out[:100])
    rc, out, err = gx("-L", "-u", "alice:secret", f"{plain}/redir?status=302&to={other}/basic")
    check("auth: credentials not sent to another host", rc == 1 and out == b"who are you", out[:100])
    dbase = f"http://127.0.0.1:{dg}/digest"
    for kind in ["md5", "sha256", "sha256-sess", "sha512-256", "userhash"]:
        rc, out, err = gx("--digest", "-u", "Mufasa:Circle of Life", f"{dbase}/{kind}")
        crc, cout, cerr = run([CURL, "-s", "--digest", "-u", "Mufasa:Circle of Life", f"{dbase}/{kind}"])
        check(f"auth: Digest {kind} (curl: {cout.decode()})", rc == 0 and out == b"digest ok", out[:100] + err[:100])
    rc, out, err = gx("--digest", "-u", "Mufasa:Circle of Life", "-d", "the body", f"{dbase}/authint")
    check("auth: Digest auth-int over a body", rc == 0 and out == b"digest ok", out[:100])
    rc, out, err = gx("--anyauth", "-u", "Mufasa:Circle of Life", f"{dbase}/sha256")
    check("auth: --anyauth takes Digest over Basic", rc == 0 and out == b"digest ok", out[:100])
    rc, out, err = gx("--digest", "-u", "Mufasa:wrong", f"{dbase}/sha256")
    check("auth: Digest refused exits 1", rc == 1, out[:100])
    # The challenge answered again with the next nc, so no 401 comes first
    # (RFC 7616 §3.4). curl 8 answers a new 401 for each request instead.
    cred = "Mufasa:Circle of Life"
    def stats():
        return gx(f"{dbase}/stats")[1]
    stats()
    u = f"{dbase}/sha256"
    rc, out, err = gx("--digest", "-u", cred, u, u, u)
    st = stats()
    check("auth: Digest's next requests answered at once, nc 1, 2, 3",
          rc == 0 and out == b"digest ok" * 3 and st == b"401 1 nc 1,2,3", st)
    us = f"{dbase}/stale/sha256"
    rc, out, err = gx("--digest", "-u", cred, us, us, us, us)
    st = stats()
    check("auth: Digest stale=true answered with the new nonce", rc == 0 and out == b"digest ok" * 4 and
          st == b"401 2 nc 1,2,3,1,2", st)
    ud = f"{dbase}/dom/sha256"
    rc, out, err = gx("--digest", "-u", cred, ud, ud, f"http://127.0.0.1:{dg}/other/sha256")
    st = stats()
    check("auth: Digest's domain param bounds the protection space", rc == 0 and out == b"digest ok" * 3 and
          st == b"401 2 nc 1,2,1", st)
    rc, out, err = gx("--digest", "-u", cred, u, f"{dbase}/md5")
    st = stats()
    check("auth: Digest's algorithm comes from each challenge", rc == 0 and out == b"digest ok" * 2 and
          st == b"401 2 nc 1,1", st)
    rc, out, err = gx("--basic", "-u", cred, u, u)
    st = stats()
    check("auth: --basic answers no Digest", rc == 1 and st == b"401 2 nc ", st)

    # gzip.
    rc, out, err = gx("--compressed", f"{plain}/gzip")
    check("gzip: decoded", rc == 0 and out == big(), err[:200])
    rc, out, err = gx("--compressed", "-i", f"{plain}/gzip")
    check("gzip: Content-Encoding and Content-Length dropped", rc == 0 and b"Content-Encoding" not in out.split(b"\r\n\r\n")[0])
    rc, out, err = gx("--compressed", f"{plain}/gzip-bad")
    check("gzip: a body cut short fails", rc == 1, err[:200])
    rc, out, err = gx("--compressed", *tls, f"https://localhost:{g13}/gzip")
    check("gzip: over TLS", rc == 0 and out == big(), err[:200])

    # Timeouts.
    t0 = time.time()
    rc, out, err = gx("-m", "1", f"{plain}/slow")
    check("timeout: -m 1 against 3 s", rc == 1 and time.time() - t0 < 2.5 and b"timed out" in err, err[:200])


def proxy_cases(gh, gi, cert, g0, g13, env_base, servers):
    go_re = r"listening 127\.0\.0\.1:(\d+)"
    m = ["-map", "origin.test=127.0.0.1"]
    px = Server([gi, "proxy", *m], go_re, "stdout")
    pa = Server([gi, "proxy", "-auth", "u:p", *m], go_re, "stdout")
    ps = Server([gi, "proxy", "-cert", cert, "-key", cert.replace("cert.pem", "key.pem"), *m], go_re, "stdout")
    sx = Server([gi, "socks5", *m], go_re, "stdout")
    sa = Server([gi, "socks5", "-auth", "u:p", *m], go_re, "stdout")
    servers += [px, pa, ps, sx, sa]
    tls = ["--cacert", cert]
    o_http = f"http://origin.test:{g0}/hello"
    o_https = f"https://origin.test:{g13}/hello"

    def gx(*a, env=None):
        p = subprocess.run([gh, *a], capture_output=True, timeout=60, env=env if env is not None else env_base)
        return p.returncode, p.stdout, p.stderr

    def logged(srv, text):
        time.sleep(0.2)
        return any(text in l for l in srv.log)

    rc, out, err = gx("-x", f"http://127.0.0.1:{px.port}", o_http)
    check("proxy: http in absolute-form", rc == 0 and out == b"hello" and logged(px, f"proxy GET {o_http}"), err[:200])
    rc, out, err = gx("-x", f"http://127.0.0.1:{px.port}", *tls, o_https)
    check("proxy: https through CONNECT", rc == 0 and out == b"hello" and logged(px, f"proxy CONNECT origin.test:{g13}"), err[:200])
    before = sum("CONNECT" in l for l in px.log)
    rc, out, err = gx("-x", f"http://127.0.0.1:{px.port}", *tls, o_https, o_https, o_https)
    time.sleep(0.2)
    check("proxy: one tunnel for three requests", rc == 0 and out == b"hello" * 3 and sum("CONNECT" in l for l in px.log) == before + 1)
    rc, out, err = gx("-x", f"http://127.0.0.1:{pa.port}", o_http)
    check("proxy: 407 without credentials exits 1", rc == 1, out[:100])
    rc, out, err = gx("-x", f"http://u:p@127.0.0.1:{pa.port}", o_http)
    check("proxy: Basic credentials from the proxy URL", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx("-x", f"http://u:p@127.0.0.1:{pa.port}", *tls, o_https)
    check("proxy: CONNECT with credentials", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx("-x", f"http://127.0.0.1:{pa.port}", *tls, o_https)
    check("proxy: CONNECT's 407 exits 1", rc == 1, err[:200])
    rc, out, err = gx("-x", f"https://localhost:{ps.port}", *tls, o_http)
    check("proxy: an https proxy for http", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx("-x", f"https://localhost:{ps.port}", *tls, o_https)
    check("proxy: an https proxy for https (TLS in TLS)", rc == 0 and out == b"hello" and logged(ps, f"proxy CONNECT origin.test:{g13}"), err[:200])
    # The session cache: the proxy's TLS and the origin's both resume on the
    # second connection (Connection: close makes one a request).
    o_tls = f"https://origin.test:{g13}/tls"
    rc, out, err = gx("-x", f"https://localhost:{ps.port}", *tls, "-H", "Connection: close", o_tls, o_tls)
    check("proxy: TLS in TLS, both resumed on the second connection",
          rc == 0 and out == b"version TLS 1.3 resumed false proto HTTP/1.1\nversion TLS 1.3 resumed true proto HTTP/1.1\n"
          and logged(ps, f"proxy CONNECT origin.test:{g13} (resumed)"), out[:200] + err[:200])
    rc, out, err = gx("-x", f"socks5h://127.0.0.1:{sx.port}", o_http)
    check("socks5: by name", rc == 0 and out == b"hello" and logged(sx, f"socks CONNECT origin.test:{g0}"), err[:200])
    rc, out, err = gx("-x", f"socks5://127.0.0.1:{sx.port}", *tls, o_https)
    check("socks5: https", rc == 0 and out == b"hello" and logged(sx, f"socks CONNECT origin.test:{g13}"), err[:200])
    rc, out, err = gx("-x", f"socks5://127.0.0.1:{sx.port}", f"http://[::1]:1/")
    check("socks5: an IPv6 address as one", logged(sx, "socks CONNECT [::1]:1"), err[:200])
    rc, out, err = gx("-x", f"socks5://u:p@127.0.0.1:{sa.port}", o_http)
    check("socks5: with RFC 1929's password", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx("-x", f"socks5://u:bad@127.0.0.1:{sa.port}", o_http)
    check("socks5: a wrong password exits 1", rc == 1, err[:200])
    env = dict(env_base, HTTP_PROXY=f"http://127.0.0.1:{px.port}", HTTPS_PROXY=f"http://127.0.0.1:{px.port}")
    rc, out, err = gx(o_http, env=env)
    check("proxy: HTTP_PROXY", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx(*tls, o_https, env=env)
    check("proxy: HTTPS_PROXY", rc == 0 and out == b"hello", err[:200])
    rc, out, err = gx(o_http, env=dict(env, NO_PROXY="origin.test"))
    check("proxy: NO_PROXY goes direct (origin.test does not resolve)", rc == 1 and b"resolve" in err, err[:200])
    rc, out, err = gx(f"http://127.0.0.1:{g0}/hello", env=env)
    check("proxy: never for loopback from the environment", rc == 0 and out == b"hello" and not logged(px, f"127.0.0.1:{g0}/hello"))
    rc, out, err = gx(o_http, env=dict(env, REQUEST_METHOD="GET"))
    check("proxy: HTTP_PROXY not used under CGI", rc == 1 and b"resolve" in err, err[:200])
    rc, out, err = gx("-x", f"http://127.0.0.1:{px.port}", "--noproxy", "origin.test", o_http)
    check("proxy: --noproxy", rc == 1 and b"resolve" in err, err[:200])


def session_cases(gh, cert, g12, g13, late, env_base):
    """TLS session resumption, as Go's server reports it on /tls."""
    def gx(*a):
        p = subprocess.run([gh, "--cacert", cert, *a], capture_output=True, timeout=60, env=env_base)
        return p.returncode, p.stdout, p.stderr
    for port, v in ((g13, "1.3"), (g12, "1.2")):
        u = f"https://localhost:{port}/tls"
        rc, out, err = gx("-H", "Connection: close", u, u, u)
        want = "".join(f"version TLS {v} resumed {r} proto HTTP/1.1\n" for r in ("false", "true", "true")).encode()
        check(f"sessions: TLS {v}, new connections resume", rc == 0 and out == want, out[:300] + err[:200])
    u = f"https://localhost:{g13}/tls"
    rc, out, err = gx("-v", "-H", "Connection: close", "-k", u, u)
    check("sessions: -k resumes too", rc == 0 and out.endswith(b"resumed true proto HTTP/1.1\n"), out[:300])
    rc, out, err = gx("-H", "Connection: close", u, f"https://127.0.0.1:{g13}/tls")
    check("sessions: one per server name (an address is another)", rc == 0 and out.count(b"resumed false") == 2, out[:300])
    # A ticket that comes while the connection is idle is read, not taken
    # for the end of the connection.
    u = f"https://localhost:{late}/"
    rc, out, err = gx("-v", "--rate", "2/s", u, u, u)
    check("sessions: a late NewSessionTicket keeps the idle connection",
          rc == 0 and err.count(b"connection reused") == 2, err[:400])


PY10 = r'''
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"to the close " * 1000)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
print("listening", s.server_address[1], flush=True)
s.serve_forever()
'''


def main():
    global only
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("-k", help="only cases whose name has this")
    args = ap.parse_args()
    only = args.k
    goose = find_goose(args.goose)
    tmp = tempfile.mkdtemp()
    servers = []
    try:
        tools = os.path.join(ROOT, "tools")
        for src, exe in (("httpd.goose", "goose-httpd"), ("http.goose", "goose-http")):
            p = subprocess.run([goose, "build", "-o", os.path.join(tmp, exe), os.path.join(tools, src)],
                               capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit(p.stdout + p.stderr)
        env = dict(os.environ, GOPROXY="off")
        subprocess.run(["go", "build", "-o", os.path.join(tmp, "gointerop"), "."], cwd=os.path.join(tools, "gointerop"),
                       env=env, check=True)
        www = os.path.join(tmp, "root")
        os.makedirs(os.path.join(www, "sub"))
        with open(os.path.join(www, "index.html"), "w") as f:
            f.write("hello from goose\n")
        with open(os.path.join(www, "sub", "a.txt"), "w") as f:
            f.write("sub\n")
        with open(os.path.join(www, "big.bin"), "wb") as f:
            f.write(big())
        os.symlink("/etc/passwd", os.path.join(www, "escape"))
        cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,DNS:origin.test,IP:127.0.0.1"], check=True, capture_output=True)
        httpd = os.path.join(tmp, "goose-httpd")
        gh = os.path.join(tmp, "goose-http")
        gi = os.path.join(tmp, "gointerop")
        port_re = r"listening on 127\.0\.0\.1:(\d+)"
        plain = Server([httpd, "--root", www, "--port", "0"], port_re)
        t12 = Server([httpd, "--root", www, "--port", "0", "--cert", cert, "--key", key, "--tls-max", "1.2"], port_re)
        t13 = Server([httpd, "--root", www, "--port", "0", "--cert", cert, "--key", key], port_re)
        servers += [plain, t12, t13]
        for srv, tls in ((plain, None), (t12, "1.2"), (t13, "1.3")):
            curl_cases(srv.port, tls, cert)
            python_cases(srv.port, tls, cert)
            scheme = "https://localhost" if tls else "http://127.0.0.1"
            gopts = ["-cacert", cert, "-tlsmax", tls] if tls else []
            rc, out, err = run([gi, "client", "-base", f"{scheme}:{srv.port}", *gopts], timeout=120)
            for line in out.decode().splitlines():
                ok = line.startswith("ok ")
                check(f"go {tls or 'tcp'}: " + line.split(" ", 1)[1].split(":")[0], ok, line)
            if rc not in (0, 1) or not out:
                check(f"go {tls or 'tcp'}: client ran", False, err.decode()[:300])
        raw_cases(plain.port)
        # goose-http against Go's server, and a Python HTTP/1.0 one.
        go_re = r"listening 127\.0\.0\.1:(\d+)"
        g0 = Server([gi, "server"], go_re, "stdout")
        g12 = Server([gi, "server", "-cert", cert, "-key", key, "-tlsmax", "1.2"], go_re, "stdout")
        g13 = Server([gi, "server", "-cert", cert, "-key", key, "-tlsmax", "1.3"], go_re, "stdout")
        servers += [g0, g12, g13]
        goose_client_cases(gh, g0.port, None, cert, "goose-http to go tcp")
        goose_client_cases(gh, g12.port, "1.2", cert, "goose-http to go 1.2")
        goose_client_cases(gh, g13.port, "1.3", cert, "goose-http to go 1.3")
        py = Server([sys.executable, "-c", PY10], r"listening (\d+)", "stdout")
        servers.append(py)
        rc, out, err = run([gh, f"http://127.0.0.1:{py.port}/", f"http://127.0.0.1:{py.port}/"])
        check("goose-http to python HTTP/1.0: bodies to the close, twice", rc == 0 and out == b"to the close " * 2000, err.decode()[:200])
        # goose-http's policy, and proxies. No proxy of the caller's environment.
        env_base = {k: v for k, v in os.environ.items() if k.lower() not in
                    ("http_proxy", "https_proxy", "no_proxy", "all_proxy", "request_method")}
        dg = Server([sys.executable, "-c", DIGEST], r"listening (\d+)", "stdout")
        servers.append(dg)
        fetch_cases(gh, gi, cert, g0.port, g13.port, dg.port, env_base)
        proxy_cases(gh, gi, cert, g0.port, g13.port, env_base, servers)
        late = Server([httpd, "--root", www, "--port", "0", "--cert", cert, "--key", key, "--late-ticket"], port_re)
        servers.append(late)
        session_cases(gh, cert, g12.port, g13.port, late.port, env_base)
        bad = 0
        for s in servers:
            for l in s.log:
                if "goose-httpd" not in l and "listening" not in l and l.strip() and s in (plain, t12, t13) and not re.match(r"^\S+ \S+ \d{3} \d+$", l.strip()):
                    bad += 1
        check("goose-httpd logged nothing unexpected", bad == 0)
    finally:
        for s in servers:
            s.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""HTTP/1.1 interop on 127.0.0.1: goose-httpd against curl, Go's net/http
and Python's http.client, and goose-http against Go's net/http server and
a Python HTTP/1.0 server; each over TCP and TLS 1.2 and 1.3.

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
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
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

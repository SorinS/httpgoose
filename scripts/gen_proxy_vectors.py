#!/usr/bin/env python3
"""Go's proxy-selection tests as vectors for test/fetch.goose.

Takes proxyForURLTests and UseProxyTests from golang.org/x/net's
http/httpproxy/proxy_test.go (the package net/http's ProxyFromEnvironment
is), runs each through that package, and writes what it answers:

  proxy  HTTP_PROXY  HTTPS_PROXY  NO_PROXY  CGI  URL  -> the proxy's URL, "-" for none, "err"
  use    NO_PROXY  host:port  -> whether the proxy is used

to test/vectors/proxy.txt. Needs golang.org/x/net in the module cache.

    python3 scripts/gen_proxy_vectors.py [--go PATH] [--xnet VERSION]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

MAIN = r'''
package main

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

type proxyForURLTest struct {
	cfg     httpproxy.Config
	req     string
	want    string
	wanterr error
}

func esc(s string) string { return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n").Replace(s) }
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return esc(s)
}

func main() {
	for _, tt := range proxyForURLTests {
		req := tt.req
		if req == "" {
			req = "http://example.com"
		}
		u, err := url.Parse(req)
		if err != nil {
			continue
		}
		cfg := tt.cfg
		p, err := cfg.ProxyFunc()(u)
		got := "-"
		if err != nil {
			got = "err"
		} else if p != nil {
			got = p.String()
		}
		cgi := "0"
		if tt.cfg.CGI {
			cgi = "1"
		}
		fmt.Printf("proxy\t%s\t%s\t%s\t%s\t%s\t%s\n", dash(tt.cfg.HTTPProxy), dash(tt.cfg.HTTPSProxy), dash(tt.cfg.NoProxy), cgi, esc(req), esc(got))
	}
	for _, np := range []string{noProxy, "*", ":1"} {
		hosts := UseProxyTests
		if np == ":1" {
			hosts = hosts[:0]
			hosts = append(hosts, struct {
				host  string
				match bool
			}{"example.com", true})
		}
		for _, t := range hosts {
			// useProxy is unexported: a config with only an HTTP proxy and
			// this NO_PROXY tells it through ProxyFunc.
			cfg := httpproxy.Config{HTTPProxy: "http://proxy.test", NoProxy: np}
			host := t.host
			u := &url.URL{Scheme: "http", Host: host + ":80"}
			p, _ := cfg.ProxyFunc()(u)
			fmt.Printf("use\t%s\t%s\t%v\n", esc(np), esc(host+":80"), p != nil)
		}
	}
}
'''


def block(src, name):
    m = re.search(r"^var " + name + r"\b.*$", src, re.M)
    if not m:
        sys.exit(f"no table {name}")
    end = src.index("\n}\n", m.start())
    return src[m.start():end + 3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default=shutil.which("go") or "go")
    ap.add_argument("--xnet", default="v0.58.0")
    args = ap.parse_args()
    modcache = subprocess.run([args.go, "env", "GOMODCACHE"], capture_output=True, text=True, check=True).stdout.strip()
    src_path = os.path.join(modcache, "golang.org", "x", f"net@{args.xnet}", "http", "httpproxy", "proxy_test.go")
    src = open(src_path, encoding="utf-8").read()
    tables = block(src, "proxyForURLTests") + "\n" + block(src, "UseProxyTests") + "\n" + \
        re.search(r"^var noProxy = .*$", src, re.M).group(0) + "\n"
    tables = tables.replace("errors.New(", "fmt.Errorf(")
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "go.mod"), "w") as f:
            f.write(f"module proxyvectors\n\ngo 1.27\n\nrequire golang.org/x/net {args.xnet}\n")
        with open(os.path.join(tmp, "main.go"), "w") as f:
            f.write(MAIN + "\n" + tables)
        env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod", GONOSUMDB="*", GONOSUMCHECK="1", GOFLAGS_EXTRA="")
        env["GOFLAGS"] = "-mod=mod"
        env["GONOSUMDB"] = "*"
        env["GOSUMDB"] = "off"
        exe = os.path.join(tmp, "proxyvectors")
        subprocess.run([args.go, "build", "-o", exe, "."], cwd=tmp, env=env, check=True)
        out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout
    ver = subprocess.run([args.go, "version"], capture_output=True, text=True).stdout.strip()
    with open(os.path.join(ROOT, "test", "vectors", "proxy.txt"), "w") as f:
        f.write(f"# golang.org/x/net {args.xnet} http/httpproxy tables, as that package answers them ({ver}); "
                "scripts/gen_proxy_vectors.py\n" + out)
    print(out.count("\nproxy") + out.startswith("proxy"), "proxy cases,", out.count("use\t"), "use cases")


if __name__ == "__main__":
    main()

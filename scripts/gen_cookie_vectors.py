#!/usr/bin/env python3
"""Go's cookie jar tests as vectors for test/cookie.goose.

Takes the tables of $GOROOT/src/net/http/cookiejar/jar_test.go (Go's own
tests and those it took from Chromium's cookie_store_unittest.h) and has
Go print them, so the expiry dates come out as Go writes them:

  test/vectors/cookiejar.txt   jarTest tables: Set-Cookie lines received
                               from a URL, the jar's content after, and
                               the Cookie lines for URLs queried after that
  test/vectors/cookiejar_units.txt
                               jarKey, defaultPath, domainAndType, isIP,
                               canonicalHost and hasDotSuffix tables

    python3 scripts/gen_cookie_vectors.py [--go PATH]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

JAR_TABLES = [("basicsTests", "fresh"), ("updateAndDeleteTests", "shared"), ("chromiumBasicsTests", "fresh"),
              ("chromiumDomainTests", "shared"), ("chromiumDeletionTests", "shared"), ("domainHandlingTests", "fresh")]
UNIT_TABLES = ["jarKeyTests", "jarKeyNilPSLTests", "defaultPathTests", "isIPTests", "canonicalHostTests",
               "hasDotSuffixTests", "domainAndTypeTests"]

MAIN = r'''
package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	errIllegalDomain   = fmt.Errorf("illegal domain")
	errMalformedDomain = fmt.Errorf("malformed domain")
)

var tNow = time.Date(2013, 1, 1, 12, 0, 0, 0, time.UTC)

func expiresIn(delta int) string {
	t := tNow.Add(time.Duration(delta) * time.Second)
	return "expires=" + t.Format(time.RFC1123)
}

type jarTest struct {
	description string
	fromURL     string
	setCookies  []string
	content     string
	queries     []query
}

type query struct {
	toURL string
	want  string
}

func esc(s string) string { return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n").Replace(s) }

func dumpJar(name, mode string, tests []jarTest) {
	fmt.Printf("group\t%s\t%s\n", name, mode)
	for _, t := range tests {
		fmt.Printf("test\t%s\nfrom\t%s\n", esc(t.description), esc(t.fromURL))
		for _, c := range t.setCookies {
			fmt.Printf("set\t%s\n", esc(c))
		}
		fmt.Printf("content\t%s\n", esc(t.content))
		for _, q := range t.queries {
			fmt.Printf("query\t%s\t%s\n", esc(q.toURL), esc(q.want))
		}
		fmt.Println("end")
	}
}

func dumpMap(name string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s\t%s\t%s\n", name, esc(k), esc(m[k]))
	}
}

func dumpBoolMap(name string, m map[string]bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s\t%s\t%v\n", name, esc(k), m[k])
	}
}

func main() {
	if len(%(args)s) > 0 && %(args)s[0] == "units" {
		dumpMap("jarKey", jarKeyTests)
		dumpMap("jarKeyNilPSL", jarKeyNilPSLTests)
		dumpMap("defaultPath", defaultPathTests)
		dumpBoolMap("isIP", isIPTests)
		dumpMap("canonicalHost", canonicalHostTests)
		for _, t := range hasDotSuffixTests {
			fmt.Printf("hasDotSuffix\t%s\t%s\t%v\n", esc(t.s), esc(t.suffix), strings.HasSuffix(t.s, "."+t.suffix))
		}
		for _, t := range domainAndTypeTests {
			fmt.Printf("domainAndType\t%s\t%s\t%s\t%v\t%v\n", esc(t.host), esc(t.domain), esc(t.wantDomain), t.wantHostOnly, t.wantErr == nil)
		}
		return
	}
%(dumps)s
}
'''


def block(src, name):
    """The source of `var name = ...` up to its closing brace at column 0."""
    m = re.search(r"^var " + name + r"\b.*$", src, re.M)
    if not m:
        sys.exit(f"no table {name} in jar_test.go")
    end = src.index("\n}\n", m.start())
    return src[m.start():end + 3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default=shutil.which("go") or "go")
    args = ap.parse_args()
    goroot = subprocess.run([args.go, "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
    src = open(os.path.join(goroot, "src", "net", "http", "cookiejar", "jar_test.go"), encoding="utf-8").read()
    expiration = re.search(r"func TestExpiration.*?jarTest(\{.*?\n\t\})\.run", src, re.S).group(1)
    parts = [block(src, n) for n, _ in JAR_TABLES] + [block(src, n) for n in UNIT_TABLES]
    parts.append("var expirationTests = [...]jarTest{" + expiration.replace("\n\t", "\n") + ",\n}\n")
    dumps = "\n".join(f'\tdumpJar("{n}", "{m}", {n}[:])' for n, m in JAR_TABLES)
    dumps += '\n\tdumpJar("expirationTests", "fresh", expirationTests[:])'
    prog = MAIN.replace("%(dumps)s", dumps).replace("%(args)s", "os.Args[1:]").replace(
        '"fmt"\n', '"fmt"\n\t"os"\n') + "\n".join(parts)
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "go.mod"), "w") as f:
            f.write("module jarvectors\n\ngo 1.27\n")
        with open(os.path.join(tmp, "main.go"), "w") as f:
            f.write(prog)
        env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod")
        exe = os.path.join(tmp, "jarvectors")
        subprocess.run([args.go, "build", "-o", exe, "."], cwd=tmp, env=env, check=True)
        jar = subprocess.run([exe], capture_output=True, text=True, check=True).stdout
        units = subprocess.run([exe, "units"], capture_output=True, text=True, check=True).stdout
    head = ("# Go's net/http/cookiejar jar_test.go tables (" + subprocess.run(
        [args.go, "version"], capture_output=True, text=True).stdout.strip() + "), from scripts/gen_cookie_vectors.py\n")
    os.makedirs(os.path.join(ROOT, "test", "vectors"), exist_ok=True)
    with open(os.path.join(ROOT, "test", "vectors", "cookiejar.txt"), "w") as f:
        f.write(head + jar)
    with open(os.path.join(ROOT, "test", "vectors", "cookiejar_units.txt"), "w") as f:
        f.write(head + units)
    print(f"{jar.count(chr(10) + 'test' + chr(9)) + jar.startswith('test')} jar tests, {units.count(chr(10))} unit lines")


if __name__ == "__main__":
    main()

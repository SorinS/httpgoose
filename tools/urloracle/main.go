// urloracle prints what Go's net/url makes of each case of a cases file:
// one line "BASEHEX REFHEX" (BASEHEX "-" for none) a case. The output has
// two lines a case: url.Parse(ref), then base.Parse(ref) (or "-" without
// a base), each "err" or "ok" and the parts, hex-encoded ("-" if empty):
// scheme opaque hasuser user haspassword password hostname port path
// hasquery query fragment. For scripts/url_differential.py.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const version = "urloracle 1"

func h(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func parts(u *url.URL) string {
	var user, pass string
	hasPass := false
	if u.User != nil {
		user = u.User.Username()
		pass, hasPass = u.User.Password()
	}
	return strings.Join([]string{"ok", h(u.Scheme), h(u.Opaque), b(u.User != nil), h(user), b(hasPass), h(pass),
		h(u.Hostname()), h(u.Port()), h(u.Path), b(u.ForceQuery || u.RawQuery != ""), h(u.RawQuery), h(u.Fragment)}, " ")
}

func unhex(s string) string {
	if s == "-" {
		return ""
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "urloracle: bad hex:", s)
		os.Exit(1)
	}
	return string(d)
}

func main() {
	cases := flag.String("cases", "", "file of cases, \"BASEHEX REFHEX\" a line")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *cases == "" {
		fmt.Fprintln(os.Stderr, "urloracle: -cases is required")
		os.Exit(2)
	}
	f, err := os.Open(*cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "urloracle:", err)
		os.Exit(1)
	}
	defer f.Close()
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 2 {
			continue
		}
		base, ref := fs[0], unhex(fs[1])
		if r, err := url.Parse(ref); err != nil {
			fmt.Fprintln(out, "err")
		} else {
			fmt.Fprintln(out, parts(r))
		}
		if base == "-" {
			fmt.Fprintln(out, "-")
			continue
		}
		bu, err := url.Parse(unhex(base))
		if err != nil {
			fmt.Fprintln(out, "err")
			continue
		}
		if r, err := bu.Parse(ref); err != nil {
			fmt.Fprintln(out, "err")
		} else {
			fmt.Fprintln(out, parts(r))
		}
	}
}

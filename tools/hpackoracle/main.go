// hpackoracle: golang.org/x/net/http2/hpack as the reference for
// scripts/hpack_differential.py.
//
//	hpackoracle gen -seed N -n K      cases: connections of header blocks
//	hpackoracle check < encoded.txt   decodes another encoder's blocks
//
// gen writes, for each of K connections, "conn LIMIT" (the decoder's
// SETTINGS_HEADER_TABLE_SIZE), then its blocks: "block HEX" and Go's
// decoding of it, "ok" with a "field NAME VALUE SENSITIVE" line each (names and values in hex, "-"
// for empty), or "error". Most blocks are Go's encoder's, from random
// header lists, with changes of the table size between them; some are one
// of those changed at random (a byte flipped, cut short, bytes inserted),
// and a connection ends after a block Go refuses. "limit N" lines say the
// encoder's table limit changed before the next block.
//
// check reads lines "conn LIMIT", "block HEX", "field ..." (what the
// block should decode to) and prints "ok" or "FAIL why" for each block.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

func h(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func unh(s string) string {
	if s == "-" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hpackoracle: bad hex")
		os.Exit(2)
	}
	return string(b)
}

var names = []string{":method", ":path", ":scheme", ":authority", ":status", "content-type", "content-length",
	"accept", "accept-encoding", "user-agent", "cookie", "set-cookie", "cache-control", "date", "etag",
	"authorization", "x-custom", "x-request-id", "location", "server", "vary", "te", "grpc-status"}
var values = []string{"GET", "POST", "/", "/index.html", "https", "http", "example.com", "200", "404", "302",
	"text/html", "gzip, deflate, br", "no-cache", "private", "Mon, 21 Oct 2013 20:13:21 GMT", "*/*",
	"Mozilla/5.0", "trailers", ""}

func randString(r *rand.Rand, max int, alphabet string) string {
	n := r.Intn(max + 1)
	b := make([]byte, n)
	for i := range b {
		if alphabet == "" {
			b[i] = byte(r.Intn(256))
		} else {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
	}
	return string(b)
}

func randField(r *rand.Rand) hpack.HeaderField {
	var f hpack.HeaderField
	switch r.Intn(5) {
	case 0, 1:
		f.Name = names[r.Intn(len(names))]
	case 2:
		f.Name = "x-" + randString(r, 12, "abcdefghijklmnopqrstuvwxyz0123456789-")
	case 3:
		f.Name = randString(r, 30, "abcdefghijklmnopqrstuvwxyz")
	default:
		f.Name = randString(r, 8, "")
	}
	switch r.Intn(5) {
	case 0, 1:
		f.Value = values[r.Intn(len(values))]
	case 2:
		f.Value = randString(r, 60, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_./:;=,")
	case 3:
		f.Value = randString(r, 300, "abc")
	default:
		f.Value = randString(r, 40, "")
	}
	f.Sensitive = r.Intn(8) == 0
	return f
}

func mutate(r *rand.Rand, b []byte) []byte {
	c := append([]byte(nil), b...)
	switch r.Intn(4) {
	case 0:
		if len(c) > 0 {
			c[r.Intn(len(c))] ^= byte(1 << r.Intn(8))
		}
	case 1:
		if len(c) > 0 {
			c = c[:r.Intn(len(c))]
		}
	case 2:
		at := r.Intn(len(c) + 1)
		ins := []byte(randString(r, 4, ""))
		c = append(c[:at], append(ins, c[at:]...)...)
	default:
		if len(c) > 0 {
			c[r.Intn(len(c))] = byte(r.Intn(256))
		}
	}
	return c
}

func gen(seed int64, n int) {
	r := rand.New(rand.NewSource(seed))
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	limits := []uint32{4096, 4096, 256, 100, 0, 1000, 64}
	for k := 0; k < n; k++ {
		limit := limits[r.Intn(len(limits))]
		fmt.Fprintf(w, "conn %d\n", limit)
		var out []byte
		enc := hpack.NewEncoder(writerFunc(func(p []byte) (int, error) { out = append(out, p...); return len(p), nil }))
		enc.SetMaxDynamicTableSizeLimit(limit)
		enc.SetMaxDynamicTableSize(limit)
		dec := hpack.NewDecoder(limit, nil)
		blocks := 1 + r.Intn(12)
		for b := 0; b < blocks; b++ {
			if r.Intn(6) == 0 {
				nl := []uint32{0, 32, 64, 100, 256, 1000, 4096}[r.Intn(7)]
				if nl > limit {
					nl = limit
				}
				enc.SetMaxDynamicTableSize(nl)
				fmt.Fprintf(w, "limit %d\n", nl)
			}
			out = out[:0]
			nf := r.Intn(10)
			for i := 0; i < nf; i++ {
				enc.WriteField(randField(r))
			}
			block := append([]byte(nil), out...)
			mutated := r.Intn(5) == 0
			if mutated {
				block = mutate(r, block)
			}
			fmt.Fprintf(w, "block %s\n", h(string(block)))
			fs, err := dec.DecodeFull(block)
			if err != nil {
				fmt.Fprintf(w, "error\n")
				break
			}
			fmt.Fprintf(w, "ok\n")
			for _, f := range fs {
				s := 0
				if f.Sensitive {
					s = 1
				}
				fmt.Fprintf(w, "field %s %s %d\n", h(f.Name), h(f.Value), s)
			}
			if mutated {
				break // the encoder's table and the decoder's may differ now
			}
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func check() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	var dec *hpack.Decoder
	var want []hpack.HeaderField
	var block []byte
	have := false
	flush := func() {
		if !have {
			return
		}
		have = false
		fs, err := dec.DecodeFull(block)
		if err != nil {
			fmt.Fprintf(w, "FAIL %v\n", err)
			return
		}
		if len(fs) != len(want) {
			fmt.Fprintf(w, "FAIL %d fields, want %d\n", len(fs), len(want))
			return
		}
		for i := range fs {
			if fs[i] != want[i] {
				fmt.Fprintf(w, "FAIL field %d: %q %q %v, want %q %q %v\n", i, fs[i].Name, fs[i].Value, fs[i].Sensitive,
					want[i].Name, want[i].Value, want[i].Sensitive)
				return
			}
		}
		fmt.Fprintf(w, "ok\n")
	}
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) == 0 {
			continue
		}
		switch p[0] {
		case "conn":
			flush()
			n, _ := strconv.Atoi(p[1])
			dec = hpack.NewDecoder(uint32(n), nil)
		case "block":
			flush()
			b, _ := hex.DecodeString(strings.TrimPrefix(p[1], "-"))
			block = b
			want = want[:0]
			have = true
		case "field":
			want = append(want, hpack.HeaderField{Name: unh(p[1]), Value: unh(p[2]), Sensitive: p[3] == "1"})
		}
	}
	flush()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hpackoracle gen -seed N -n K | check")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		fs := flag.NewFlagSet("gen", flag.ExitOnError)
		seed := fs.Int64("seed", 1, "random seed")
		n := fs.Int("n", 1000, "connections")
		fs.Parse(os.Args[2:])
		gen(*seed, *n)
	case "check":
		check()
	default:
		fmt.Fprintln(os.Stderr, "hpackoracle: gen or check")
		os.Exit(2)
	}
}

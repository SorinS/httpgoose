// gointerop: Go's net/http against this package's tools, on 127.0.0.1.
//
//	gointerop server -addr 127.0.0.1:0 [-cert c.pem -key k.pem -tlsmax 1.2|1.3]
//	gointerop client -base URL [-cacert c.pem -tlsmax 1.2|1.3]
//	gointerop proxy -addr 127.0.0.1:0 [-auth user:pass] [-cert c.pem -key k.pem] [-map host=addr,...]
//	gointerop socks5 -addr 127.0.0.1:0 [-auth user:pass] [-map host=addr,...]
//
// The server prints "listening ADDR" and serves /hello, /chunked,
// /trailer, /big, /echo, /status/N and /close, and for goose-http's
// policy: /redir?status=N&to=URL, /chain/N, /inspect (what arrived:
// method, body length, fields; X-Length and X-TE: the Content-Length and
// Transfer-Encoding), /setcookie?c=LINE..., /cookies, /basic
// and /bearer (credentials alice:secret, token tok123), /gzip and
// /gzip-bad (a 1 MiB body gzipped, and cut short), /slow (3 s), /tls
// (the connection's TLS version, whether it resumed, and the protocol). The
// client checks goose-httpd: files, HEAD, 404, bodies of several sizes,
// chunked uploads, connection reuse, and the TLS version; one "ok NAME"
// or "FAIL NAME: why" a line, exit status 1 if any failed.
//
// The proxy is a forward HTTP proxy (absolute-form requests, and CONNECT),
// over TLS with -cert; socks5 a SOCKS5 server (RFC 1928, RFC 1929's
// password with -auth). Both connect names in -map to the address given
// there (so a made-up name reaches a server on 127.0.0.1), and print a
// line a request: "proxy METHOD TARGET" (and " (resumed)" over a resumed
// TLS session) or "socks CONNECT HOST:PORT".
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "gointerop 2"

func big() []byte {
	b := make([]byte, 1<<20)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func tlsVersion(s string) uint16 {
	if s == "1.2" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

func serve(addr, cert, key, tlsmax string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") })
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		for _, p := range []string{"one ", "two ", "three"} {
			io.WriteString(w, p)
			w.(http.Flusher).Flush()
		}
	})
	mux.HandleFunc("/trailer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Sum")
		io.WriteString(w, "body")
		w.(http.Flusher).Flush()
		w.Header().Set("X-Sum", "42")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { w.Write(big()) })
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write(b)
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		w.WriteHeader(n)
	})
	mux.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "closing")
	})
	policy(mux)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gointerop:", err)
		os.Exit(1)
	}
	fmt.Println("listening", ln.Addr().String())
	os.Stdout.Sync()
	srv := &http.Server{Handler: mux}
	if cert != "" {
		srv.TLSConfig = &tls.Config{MaxVersion: tlsVersion(tlsmax), NextProtos: []string{"http/1.1"}}
		err = srv.ServeTLS(ln, cert, key)
	} else {
		err = srv.Serve(ln)
	}
	fmt.Fprintln(os.Stderr, "gointerop:", err)
	os.Exit(1)
}

type checker struct{ failed bool }

func (c *checker) check(name string, err error) {
	if err != nil {
		c.failed = true
		fmt.Printf("FAIL %s: %v\n", name, err)
	} else {
		fmt.Printf("ok %s\n", name)
	}
}

func client(base, cacert, tlsmax string) {
	tr := &http.Transport{ForceAttemptHTTP2: false}
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gointerop:", err)
			os.Exit(2)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tlsVersion(tlsmax), MaxVersion: tlsVersion(tlsmax),
			NextProtos: []string{"http/1.1"}}
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var c checker
	get := func(path string) (*http.Response, []byte, error) {
		r, err := hc.Get(base + path)
		if err != nil {
			return nil, nil, err
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		return r, b, err
	}
	expect := func(r *http.Response, b []byte, err error, status int, body []byte) error {
		if err != nil {
			return err
		}
		if r.StatusCode != status {
			return fmt.Errorf("status %d, want %d", r.StatusCode, status)
		}
		if body != nil && !bytes.Equal(b, body) {
			return fmt.Errorf("body of %d bytes differs (want %d)", len(b), len(body))
		}
		return nil
	}
	r, b, err := get("/index.html")
	c.check("GET a file", expect(r, b, err, 200, []byte("hello from goose\n")))
	r, b, err = get("/big.bin")
	c.check("GET 1 MiB", expect(r, b, err, 200, big()))
	r, b, err = get("/missing")
	c.check("404", expect(r, b, err, 404, nil))
	r, b, err = get("/sub")
	if err == nil && r.Header.Get("Location") != "/sub/" {
		err = fmt.Errorf("Location %q", r.Header.Get("Location"))
	}
	c.check("301 to the directory", expect(r, b, err, 301, nil))
	hr, err := hc.Head(base + "/big.bin")
	if err == nil {
		hr.Body.Close()
		if hr.ContentLength != 1<<20 {
			err = fmt.Errorf("HEAD Content-Length %d", hr.ContentLength)
		}
	}
	c.check("HEAD", err)
	for _, n := range []int{0, 1, 100, 65536, 1 << 20} {
		body := big()[:n]
		pr, err := hc.Post(base+"/echo", "application/octet-stream", bytes.NewReader(body))
		var pb []byte
		if err == nil {
			pb, err = io.ReadAll(pr.Body)
			pr.Body.Close()
		}
		c.check(fmt.Sprintf("POST %d bytes", n), expect(pr, pb, err, 200, body))
	}
	// A body of unknown length: Go sends it chunked.
	pr, err := hc.Post(base+"/echo", "text/plain", io.MultiReader(strings.NewReader("chunked "), strings.NewReader("upload")))
	var pb []byte
	if err == nil {
		pb, err = io.ReadAll(pr.Body)
		pr.Body.Close()
	}
	c.check("POST chunked", expect(pr, pb, err, 200, []byte("chunked upload")))
	// Reuse: a second request on the first one's connection.
	reused := 0
	for i := 0; i < 3; i++ {
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				reused++
			}
		}}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", base+"/index.html", nil)
		r, err := hc.Do(req)
		if err == nil {
			io.ReadAll(r.Body)
			r.Body.Close()
		}
	}
	if reused < 3 {
		err = fmt.Errorf("%d of 3 requests reused a connection", reused)
	} else {
		err = nil
	}
	c.check("keep-alive", err)
	req, _ := http.NewRequest("DELETE", base+"/index.html", nil)
	dr, err := hc.Do(req)
	if err == nil {
		io.ReadAll(dr.Body)
		dr.Body.Close()
		if dr.StatusCode != 405 || dr.Header.Get("Allow") == "" {
			err = fmt.Errorf("status %d, Allow %q", dr.StatusCode, dr.Header.Get("Allow"))
		}
	}
	c.check("405 with Allow", err)
	if cacert != "" {
		r, err := hc.Get(base + "/index.html")
		if err == nil {
			io.ReadAll(r.Body)
			r.Body.Close()
			if r.TLS == nil || r.TLS.Version != tlsVersion(tlsmax) || r.TLS.NegotiatedProtocol != "http/1.1" {
				err = fmt.Errorf("TLS %x, ALPN %q", r.TLS.Version, r.TLS.NegotiatedProtocol)
			}
		}
		c.check("TLS "+tlsmax+" with ALPN http/1.1", err)
	}
	if c.failed {
		os.Exit(1)
	}
}

// The endpoints that goose-http's redirects, cookies, credentials and
// gzip are checked against.
func policy(mux *http.ServeMux) {
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		n, _ := strconv.Atoi(r.URL.Query().Get("status"))
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(n)
	})
	mux.HandleFunc("/chain/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/chain/"))
		if n <= 0 {
			io.WriteString(w, "chain end")
			return
		}
		http.Redirect(w, r, "/chain/"+strconv.Itoa(n-1), http.StatusFound)
	})
	mux.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.Header().Set("X-Body", strconv.Itoa(len(b)))
		w.Header().Set("X-Length", strconv.FormatInt(r.ContentLength, 10))
		w.Header().Set("X-TE", strings.Join(r.TransferEncoding, ","))
		var names []string
		for k := range r.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Fprintf(w, "method %s\nbody %d %s\nhost %s\n", r.Method, len(b), b, r.Host)
		for _, k := range names {
			fmt.Fprintf(w, "%s: %s\n", k, strings.Join(r.Header[k], ", "))
		}
	})
	mux.HandleFunc("/tls", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			io.WriteString(w, "none\n")
			return
		}
		fmt.Fprintf(w, "version %s resumed %v proto %s\n", tls.VersionName(r.TLS.Version), r.TLS.DidResume, r.Proto)
	})
	mux.HandleFunc("/setcookie", func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.URL.Query()["c"] {
			w.Header().Add("Set-Cookie", c)
		}
		io.WriteString(w, "set")
	})
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Cookie"))
	})
	mux.HandleFunc("/basic", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "alice" || p != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="go", charset="UTF-8"`)
			w.WriteHeader(401)
			io.WriteString(w, "who are you")
			return
		}
		io.WriteString(w, "hello alice")
	})
	mux.HandleFunc("/bearer", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="go"`)
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, "token ok")
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Write(big())
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		zw.Write(big())
		zw.Close()
	})
	mux.HandleFunc("/gzip-bad", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(big())
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes()[:buf.Len()-10])
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		io.WriteString(w, "slow")
	})
}

// The address a name in -map stands for, else the address itself.
type dialMap map[string]string

func (m dialMap) addr(hostport string) string {
	if a, ok := m[hostport]; ok {
		return a
	}
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		if a, ok := m[host]; ok {
			_, mport, _ := net.SplitHostPort(a)
			if mport == "" {
				return net.JoinHostPort(a, port)
			}
			return a
		}
	}
	return hostport
}

func parseMap(s string) dialMap {
	m := dialMap{}
	for _, kv := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

var logMu sync.Mutex

func logLine(format string, a ...any) {
	logMu.Lock()
	fmt.Printf(format+"\n", a...)
	os.Stdout.Sync()
	logMu.Unlock()
}

func proxyServe(addr, auth, cert, key string, m dialMap) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return net.Dial(network, m.addr(a))
		},
		Proxy: nil,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.RequestURI
		if auth != "" {
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			if r.Header.Get("Proxy-Authorization") != want {
				logLine("proxy %s %s refused", r.Method, target)
				w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
				w.WriteHeader(407)
				return
			}
		}
		if r.TLS != nil && r.TLS.DidResume {
			logLine("proxy %s %s (resumed)", r.Method, target)
		} else {
			logLine("proxy %s %s", r.Method, target)
		}
		if r.Method == "CONNECT" {
			up, err := net.Dial("tcp", m.addr(r.Host))
			if err != nil {
				w.WriteHeader(502)
				return
			}
			hj, _ := w.(http.Hijacker)
			conn, brw, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() { io.Copy(up, brw); up.Close() }()
			io.Copy(conn, up)
			conn.Close()
			return
		}
		if r.URL.Scheme == "" {
			w.WriteHeader(400)
			return
		}
		out := r.Clone(context.Background())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")
		out.Header.Del("Proxy-Connection")
		resp, err := tr.RoundTrip(out)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gointerop:", err)
		os.Exit(1)
	}
	fmt.Println("listening", ln.Addr().String())
	os.Stdout.Sync()
	srv := &http.Server{Handler: h}
	if cert != "" {
		srv.TLSConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
		err = srv.ServeTLS(ln, cert, key)
	} else {
		err = srv.Serve(ln)
	}
	fmt.Fprintln(os.Stderr, "gointerop:", err)
	os.Exit(1)
}

func socksServe(addr, auth string, m dialMap) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gointerop:", err)
		os.Exit(1)
	}
	fmt.Println("listening", ln.Addr().String())
	os.Stdout.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go socksConn(c, auth, m)
	}
}

func socksConn(c net.Conn, auth string, m dialMap) {
	defer c.Close()
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	io.ReadFull(br, methods)
	want := byte(0)
	if auth != "" {
		want = 2
	}
	if !bytes.Contains(methods, []byte{want}) {
		c.Write([]byte{5, 0xff})
		logLine("socks refused: no acceptable method")
		return
	}
	c.Write([]byte{5, want})
	if want == 2 {
		v := make([]byte, 2)
		io.ReadFull(br, v)
		u := make([]byte, v[1])
		io.ReadFull(br, u)
		pl := make([]byte, 1)
		io.ReadFull(br, pl)
		p := make([]byte, pl[0])
		io.ReadFull(br, p)
		if string(u)+":"+string(p) != auth {
			c.Write([]byte{1, 1})
			logLine("socks refused: bad password")
			return
		}
		c.Write([]byte{1, 0})
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		a := make([]byte, 4)
		io.ReadFull(br, a)
		host = net.IP(a).String()
	case 4:
		a := make([]byte, 16)
		io.ReadFull(br, a)
		host = net.IP(a).String()
	case 3:
		l := make([]byte, 1)
		io.ReadFull(br, l)
		a := make([]byte, l[0])
		io.ReadFull(br, a)
		host = string(a)
	default:
		return
	}
	pb := make([]byte, 2)
	io.ReadFull(br, pb)
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	logLine("socks CONNECT %s", target)
	up, err := net.Dial("tcp", m.addr(target))
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	go func() { io.Copy(up, br); up.Close() }()
	io.Copy(c, up)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gointerop server|client|proxy|socks5 ...")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on")
	cert := fs.String("cert", "", "certificate chain (PEM)")
	key := fs.String("key", "", "private key (PEM)")
	tlsmax := fs.String("tlsmax", "1.3", "the TLS version: 1.2 or 1.3")
	base := fs.String("base", "", "the server's base URL")
	cacert := fs.String("cacert", "", "roots for the server's certificate (PEM)")
	auth := fs.String("auth", "", "proxy credentials, user:pass")
	maps := fs.String("map", "", "host=addr,... for the proxies")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "server":
		serve(*addr, *cert, *key, *tlsmax)
	case "client":
		client(*base, *cacert, *tlsmax)
	case "proxy":
		proxyServe(*addr, *auth, *cert, *key, parseMap(*maps))
	case "socks5":
		socksServe(*addr, *auth, parseMap(*maps))
	default:
		fmt.Fprintln(os.Stderr, "usage: gointerop server|client|proxy|socks5 ...")
		os.Exit(2)
	}
}

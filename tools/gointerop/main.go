// gointerop: Go's net/http against this package's tools, on 127.0.0.1.
//
//	gointerop server -addr 127.0.0.1:0 [-cert c.pem -key k.pem -tlsmax 1.2|1.3]
//	gointerop client -base URL [-cacert c.pem -tlsmax 1.2|1.3]
//
// The server prints "listening ADDR" and serves /hello, /chunked,
// /trailer, /big, /echo, /status/N and /close. The client checks
// goose-httpd: files, HEAD, 404, bodies of several sizes, chunked
// uploads, connection reuse, and the TLS version; one "ok NAME" or
// "FAIL NAME: why" a line, exit status 1 if any failed.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
)

const version = "gointerop 1"

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

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gointerop server|client ...")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on")
	cert := fs.String("cert", "", "certificate chain (PEM)")
	key := fs.String("key", "", "private key (PEM)")
	tlsmax := fs.String("tlsmax", "1.3", "the TLS version: 1.2 or 1.3")
	base := fs.String("base", "", "the server's base URL")
	cacert := fs.String("cacert", "", "roots for the server's certificate (PEM)")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "server":
		serve(*addr, *cert, *key, *tlsmax)
	case "client":
		client(*base, *cacert, *tlsmax)
	default:
		fmt.Fprintln(os.Stderr, "usage: gointerop server|client ...")
		os.Exit(2)
	}
}

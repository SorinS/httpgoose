// h1oracle sends each request of a cases file (one hex-encoded request per
// line) to Go's net/http server on 127.0.0.1 and prints one verdict a line:
// "ok KIND LENGTH BODYHEX" when the handler ran and read the body (KIND
// none, length or chunked), "bodyerr KIND" when reading the body failed,
// or "status N" when the server answered without running the handler.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "h1oracle 1"

func main() {
	cases := flag.String("cases", "", "file of hex-encoded requests, one a line")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *cases == "" {
		fmt.Fprintln(os.Stderr, "h1oracle: -cases is required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*cases)
	if err != nil {
		fmt.Fprintln(os.Stderr, "h1oracle:", err)
		os.Exit(1)
	}
	// The server closes first (Connection: close), so its side of each
	// connection waits in TIME_WAIT and holds the client's port: thousands
	// of cases run out of ephemeral ports on one server port. They are
	// spread over several, each with its own ports.
	var addrs []string
	for i := 0; i < 16; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, "h1oracle:", err)
			os.Exit(1)
		}
		srv := &http.Server{Handler: http.HandlerFunc(handle), ReadTimeout: 5 * time.Second}
		go srv.Serve(ln)
		addrs = append(addrs, ln.Addr().String())
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		req, err := hex.DecodeString(strings.TrimSpace(line))
		if err != nil {
			fmt.Fprintln(os.Stderr, "h1oracle: bad case:", err)
			os.Exit(1)
		}
		fmt.Fprintln(out, verdict(addrs[i%len(addrs)], req))
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	kind := "none"
	if len(r.TransferEncoding) > 0 {
		kind = "chunked"
	} else if r.ContentLength > 0 {
		kind = "length"
	}
	body, err := io.ReadAll(r.Body)
	w.Header().Set("Connection", "close")
	if err != nil {
		fmt.Fprintf(w, "bodyerr %s", kind)
		return
	}
	fmt.Fprintf(w, "ok %s %d %x", kind, len(body), body)
}

func verdict(addr string, req []byte) string {
	// Each connection is closed with a reset (linger 0) once its response
	// is read, leaving no TIME_WAIT on this side, and a refused dial is
	// tried again.
	var c net.Conn
	var err error
	// macOS keeps a port in TIME_WAIT from being any connection's local
	// port, so past about 16,000 cases a dial waits for ports to come free
	// (up to a minute; TIME_WAIT is 30 seconds there).
	for try := 0; try < 600; try++ {
		if c, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "h1oracle: dial:", err)
		return "dialerr"
	}
	defer c.Close()
	defer c.(*net.TCPConn).SetLinger(0)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write(req)
	c.(*net.TCPConn).CloseWrite()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "noresponse"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 && (strings.HasPrefix(string(b), "ok ") || strings.HasPrefix(string(b), "bodyerr ")) {
		return string(b)
	}
	return fmt.Sprintf("status %d", resp.StatusCode)
}

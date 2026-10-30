# httpgoose

HTTP for Goose: HTTP/1.1 now, HTTP/2 to follow, with HTTPS through
[tlsgoose](../tlsgoose.git). The protocol code does no I/O: it parses and
writes byte strings, and the caller owns the sockets.

| Module | What |
|---|---|
| `http` | RFC 9110's syntax: tokens, field names and values, fields of a parsed message, status codes, building field sections |
| `http.h1` | RFC 9112: request and response heads, body framing (§6.3), the chunked coding (§7.1), writing messages |
| `http.url` | RFC 3986 URLs as Go's net/url reads them: parsing, resolving references (§5.2), percent-encoding, queries and forms, IP addresses, Punycode host names |
| `http.cookie` | RFC 6265 cookies: Set-Cookie as a user agent parses it, a jar that behaves as Go's net/http/cookiejar, publicsuffix.org's list (built in on request), curl's cookies.txt |
| `http.auth` | RFC 9110 §11 challenges; Basic (RFC 7617), Bearer (RFC 6750), Digest (RFC 7616: MD5, SHA-256, SHA-512-256, -sess, auth and auth-int, userhash) |
| `http.flate` | gzip (RFC 1952, several members), zlib (RFC 1950) and raw DEFLATE (RFC 1951) decoding, fed as the body comes |
| `http.conn1` | HTTP/1.1 connections, server and client: events for heads, body data and ends; requests answered in order; keep-alive and close; HEAD, 1xx, 204, 304; 100-continue; body limits (413) |

```goose
import http from "../httpgoose.git";
import http.h1;

let lim = http::default_limits();
let h, n = http::parse_request(buf, lim);      // n > 0: the head's length; 0: need more; < 0: -status
if n > 0 && http::check_request(buf, h) == 0 {
    let fr, err = http::request_framing(buf, h);   // BODY_NONE, BODY_LENGTH (fr.length) or BODY_CHUNKED
    let method = buf[h.method.pos..h.method.end];
}
```

A parsed head holds positions in the caller's buffer, not copies, and
nothing in the package keeps a large buffer inside a struct.

A server connection, the caller keeping the bytes that arrive:

```goose
import http.conn1;

var c = http::server_conn(http::server_options());
let ev, h = http::server_read(c, buf, body, trailer, out);
// EV_REQUEST (h's spans point into buf), EV_BODY, EV_END, EV_NEED_MORE,
// EV_WAIT (answer this request first), EV_ERROR (out holds the answer)
// then drop ev.used bytes from buf
http::server_respond(c, 200, fields, length, out);   // length -1: chunked
http::server_body(c, data, out);
http::server_end(c, trailer_fields, out);           // then http::closing(c)?
```

A connection reads the next request only after the response to the one
before has ended, so pipelined requests are answered in order. It closes
after a response that ended before its request's body was read (so no
unread body is taken for a request), after HTTP/1.0 without keep-alive,
Connection: close from either side, and every error.

## Strictness

Two parsers that read one byte stream as different messages are how
request smuggling works, so the parser takes one reading of each message
and refuses what could be read another way. Against Go's net/http server
(`scripts/h1_differential.py`, below) this package never takes a request
Go refuses and never frames a body differently. Where it refuses what Go
takes, each case is one of these rules:

| Refused | Answered | Why |
|---|---|---|
| A bare LF or bare CR ending a line | 400 | RFC 9112 §2.2 lets a recipient take a bare LF; a parser in front that does not would see other lines |
| A line folded onto the one before (obs-fold) | 400 | §5.2: reject or unfold; Go unfolds |
| Both Transfer-Encoding and Content-Length | 400 | §6.3 point 3: reject, or use Transfer-Encoding and close; Go does the second |
| Transfer-Encoding in an HTTP/1.0 request | 400 | §6.1: faulty framing; Go ignores the field and reads no body |
| CONNECT without Host | 400 | §3.2: every HTTP/1.1 request needs Host; Go exempts CONNECT |
| `*` as the target of a method other than OPTIONS | 400 | §3.2.4 |

And these, which Go refuses as well:

- Content-Length: digits only, with any number of leading zeros and at
  most 18 significant digits; repeated lines must be the same text; a
  list (`5, 5`) is refused (RFC 9110 §8.6 permits either).
- Transfer-Encoding: `chunked` alone, in one or more lines; an empty list
  element (`chunked,`) is refused although RFC 9110 §5.6.1.2 has recipients
  skip them, as a parser in front might not see chunked in it; chunked
  twice, or with parameters, is 400; other codings before chunked are 501
  (not decoded here).
- No whitespace between a field name and its colon (§5.1); field values
  without NUL, CR, LF or other controls; HTTP/1.1 requests with exactly one
  Host, of an authority's characters.
- Chunk sizes of at most 15 hex digits; chunk extensions and trailers
  parsed to their grammar, not skipped, within limits.

Limits (`http::Limits`): 64 KiB of head (431), 8 KiB of request line
(414), 128 field lines (431), 4 KiB of extensions on a chunk line, 16 KiB
of trailer.

## Tools

`tools/httpd.goose` (goose-httpd) serves static files over HTTP/1.1, plain
or HTTPS through tlsgoose (`--tls-max 1.2` holds it to TLS 1.2), on
127.0.0.1 unless told otherwise, one process a connection; GET and HEAD,
and POST /echo. Paths are percent-decoded once, refuse `..` segments and
NUL, and must resolve, symbolic links followed, inside the root.
`tools/http.goose` (goose-http) is a client of http and https URLs,
keeping a connection for URLs of one origin, checking certificates
against `--cacert` or the system's roots.

```bash
goose build tools/httpd.goose && tools/goose-httpd --root site --port 8080 [--cert c.pem --key k.pem --tls-max 1.2]
goose build tools/http.goose && tools/goose-http [-X M] [-d DATA] [-H 'N: v'] [-i] [--chunked] [--cacert c.pem] URL...
```

## Tests

```bash
python3 scripts/run_tests.py [--native]        # test/*.goose at -O0, -O2, --debug (and natively)
python3 scripts/h1_differential.py [--seed N] [--random N] [-v]
python3 scripts/url_differential.py [--seed N] [--random N] [-v]
```

`url_differential.py` parses every string literal of Go's net/url tests,
RFC 3986 §5.4's examples and generated URLs with `http.url` and with Go's
url.Parse, resolves them against bases, and compares every part. They
agree except where Go departs from RFC 3986 §5.2.2, counted apart: a
reference with an empty authority (`//?q`), which Go cannot tell from none
and so keeps the base's host, and a base with an empty query (`x?`), whose
`?` Go drops.

`interop.py` runs goose-httpd against curl (OpenSSL's, for TLS 1.3),
Go's net/http client and Python's http.client, and goose-http against
Go's net/http server and a Python HTTP/1.0 server, each over TCP, TLS 1.2
and TLS 1.3, all on 127.0.0.1: files up to 1 MiB, HEAD, 301, 404, 405,
bodies of 0 to 1 MiB with lengths and chunked, Expect: 100-continue,
connection reuse, Connection: close, trailers, bodies to the close, ALPN
http/1.1, and raw bytes (pipelining, CL with TE, bare LF, a 64 KiB head).

```bash
python3 scripts/interop.py [-k NAME]
```

`h1_differential.py` generates requests that vary what smuggling turns on
(the request line, Host, Content-Length and Transfer-Encoding names and
values, line endings, whitespace, duplicates, chunked bodies), and gives
the same bytes to `tools/h1verdict.goose` and to `tools/h1oracle`, Go's
`http.Server` on 127.0.0.1. It fails if the two ever frame a body
differently.

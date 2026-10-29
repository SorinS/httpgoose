# httpgoose

HTTP for Goose: HTTP/1.1 now, HTTP/2 to follow, with HTTPS through
[tlsgoose](../tlsgoose.git). The protocol code does no I/O: it parses and
writes byte strings, and the caller owns the sockets.

| Module | What |
|---|---|
| `http` | RFC 9110's syntax: tokens, field names and values, fields of a parsed message, status codes, building field sections |
| `http.h1` | RFC 9112: request and response heads, body framing (§6.3), the chunked coding (§7.1), writing messages |

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

## Tests

```bash
python3 scripts/run_tests.py [--native]        # test/*.goose at -O0, -O2, --debug (and natively)
python3 scripts/h1_differential.py [--seed N] [--random N] [-v]
```

`h1_differential.py` generates requests that vary what smuggling turns on
(the request line, Host, Content-Length and Transfer-Encoding names and
values, line endings, whitespace, duplicates, chunked bodies), and gives
the same bytes to `tools/h1verdict.goose` and to `tools/h1oracle`, Go's
`http.Server` on 127.0.0.1. It fails if the two ever frame a body
differently.

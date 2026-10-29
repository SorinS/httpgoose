// HTTP/1.1 parsing (RFC 9112): request and response heads, the checks
// against request smuggling, framing, the chunked coding fed whole and a
// byte at a time, and writing messages.

import std;
import http from "..";
import http.h1;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 30 { print("FAIL ", what); } }
}

// A request through everything a server does before its body: the head,
// the target and Host, the framing. The result: the error (negative),
// NEED_MORE (0), or 1; and the framing.
fn request(m: const u8[:]) -> i64, http::Framing {
    let lim = http::default_limits();
    var none = http::Framing { kind: http::BODY_NONE, length: 0 };
    let h, n = http::parse_request(m, lim);
    if n <= 0 { return n, none; }
    let e = http::check_request(m, h);
    if e != 0 { return e, none; }
    let fr, ef = http::request_framing(m, h);
    if ef != 0 { return ef, none; }
    return 1, fr;
}

fn ok(what: const u8[:], m: const u8[:], kind: u8, length: i64) {
    let r, fr = request(m);
    check(what, r == 1 && fr.kind == kind && fr.length == length);
    if r != 1 || fr.kind != kind || fr.length != length { print("      got ", r, " kind ", fr.kind, " length ", fr.length); }
}

fn bad(what: const u8[:], m: const u8[:], want: i64) {
    let r, fr = request(m);
    check(what, r == want);
    if r != want { print("      got ", r, ", wanted ", want); }
}

fn requests() {
    let N = http::BODY_NONE;
    ok("simple GET", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", N, 0);
    ok("HTTP/1.0 without Host", "GET / HTTP/1.0\r\n\r\n", N, 0);
    ok("Content-Length", "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", http::BODY_LENGTH, 5);
    ok("Content-Length 0", "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", N, 0);
    ok("Content-Length with leading zeros", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 007\r\n\r\n", http::BODY_LENGTH, 7);
    ok("Content-Length with twenty leading zeros", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 000000000000000000007\r\n\r\n", http::BODY_LENGTH, 7);
    ok("Content-Length of 18 digits", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999999999999999\r\n\r\n", http::BODY_LENGTH, 999999999999999999);
    ok("Content-Length repeated, the same", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n", http::BODY_LENGTH, 4);
    ok("chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", http::BODY_CHUNKED, 0);
    ok("chunked, any case", "POST / HTTP/1.1\r\nHost: a\r\ntransfer-encoding: ChUnKeD\r\n\r\n", http::BODY_CHUNKED, 0);
    ok("leading empty line", "\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n", N, 0);
    ok("absolute-form", "GET http://a/b HTTP/1.1\r\nHost: a\r\n\r\n", N, 0);
    ok("authority-form for CONNECT", "CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n", N, 0);
    ok("asterisk-form for OPTIONS", "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", N, 0);
    ok("HTTP/1.2 taken as 1.x", "GET / HTTP/1.2\r\nHost: a\r\n\r\n", N, 0);
    ok("an empty field value", "GET / HTTP/1.1\r\nHost: a\r\nX-Empty:\r\n\r\n", N, 0);
    ok("obs-text in a value", "GET / HTTP/1.1\r\nHost: a\r\nX-T: caf\xc3\xa9\r\n\r\n", N, 0);
    ok("tabs around a value", "GET / HTTP/1.1\r\nHost: a\r\nX-T:\t v \t\r\n\r\n", N, 0);
    ok("Host with a port and IPv6", "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", N, 0);

    let B = http::ERR_BAD_REQUEST;
    // The request line
    bad("two spaces after the method", "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("tab for a space", "GET\t/ HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("a space in the target", "GET /a b HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("no version", "GET /\r\nHost: a\r\n\r\n", B);
    bad("lowercase http", "GET / http/1.1\r\nHost: a\r\n\r\n", B);
    bad("trailing space after the version", "GET / HTTP/1.1 \r\nHost: a\r\n\r\n", B);
    bad("a method with a non-token byte", "GE(T / HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("a control byte in the target", "GET /\x01 HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("a non-ASCII byte in the target", "GET /caf\xc3\xa9 HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("HTTP/2.0", "GET / HTTP/2.0\r\nHost: a\r\n\r\n", http::ERR_VERSION);
    bad("HTTP/0.9 style", "GET / HTTP/0.9\r\nHost: a\r\n\r\n", http::ERR_VERSION);
    bad("five empty lines before", "\r\n\r\n\r\n\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("a relative target", "GET a/b HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("asterisk-form for GET", "GET * HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("CONNECT to a path", "CONNECT /x HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("CONNECT without a port", "CONNECT a.example HTTP/1.1\r\nHost: a\r\n\r\n", B);
    bad("CONNECT with userinfo", "CONNECT u@a.example:443 HTTP/1.1\r\nHost: a\r\n\r\n", B);
    // Line endings
    bad("bare LF after the request line", "GET / HTTP/1.1\nHost: a\r\n\r\n", B);
    bad("bare LF after a field", "GET / HTTP/1.1\r\nHost: a\n\r\n", B);
    bad("bare LF to end the head", "GET / HTTP/1.1\r\nHost: a\r\n\n", B);
    bad("bare CR in a value", "GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n", B);
    // Field lines
    bad("a space before the colon", "GET / HTTP/1.1\r\nHost : a\r\n\r\n", B);
    bad("a tab before the colon", "GET / HTTP/1.1\r\nHost\t: a\r\n\r\n", B);
    bad("obs-fold", "GET / HTTP/1.1\r\nHost: a\r\nX: b\r\n c\r\n\r\n", B);
    bad("a line starting with a space", "GET / HTTP/1.1\r\n Host: a\r\n\r\n", B);
    bad("no colon", "GET / HTTP/1.1\r\nHost: a\r\nX-Nothing\r\n\r\n", B);
    bad("an empty name", "GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n", B);
    bad("NUL in a value", "GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n", B);
    bad("DEL in a value", "GET / HTTP/1.1\r\nHost: a\r\nX: a\x7fb\r\n\r\n", B);
    bad("a name with a non-token byte", "GET / HTTP/1.1\r\nHost: a\r\nX\"Y: v\r\n\r\n", B);
    // Host
    bad("HTTP/1.1 without Host", "GET / HTTP/1.1\r\n\r\n", B);
    bad("two Host lines", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", B);
    bad("Host with a space", "GET / HTTP/1.1\r\nHost: a b\r\n\r\n", B);
    bad("Host with a slash", "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n", B);
    bad("Host with userinfo", "GET / HTTP/1.1\r\nHost: u@a\r\n\r\n", B);
    // Smuggling: Content-Length
    bad("Content-Length repeated, different", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n", B);
    bad("Content-Length as a list, different", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4, 5\r\n\r\n", B);
    bad("Content-Length with a sign", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +4\r\n\r\n", B);
    bad("Content-Length negative", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", B);
    bad("Content-Length in hex", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x10\r\n\r\n", B);
    bad("Content-Length with a space inside", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1 0\r\n\r\n", B);
    bad("Content-Length empty", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n", B);
    bad("Content-Length past i64", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", B);
    bad("Content-Length with an empty element", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4,\r\n\r\n", B);
    bad("Content-Length as a list of the same", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4, 4\r\n\r\n", B);
    bad("Content-Length repeated, written differently", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 04\r\n\r\n", B);
    // Smuggling: Transfer-Encoding
    bad("CL.TE: both", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", B);
    bad("TE.CL: both, the other order", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n", B);
    bad("TE in HTTP/1.0", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", B);
    bad("TE: xchunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", B);
    bad("TE: chunked then identity", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n", B);
    bad("TE: chunked twice", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", B);
    bad("TE: chunked in two lines", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", B);
    bad("TE: chunked, then another line", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n", B);
    bad("TE: a quoted chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n", B);
    bad("TE: chunked with a parameter", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;q=1\r\n\r\n", B);
    bad("TE: empty", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n\r\n", B);
    bad("TE: chunked and an empty element", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked,\r\n\r\n", B);
    bad("TE: an empty element and chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: , chunked\r\n\r\n", B);
    bad("TE: a vertical tab", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\x0bchunked\r\n\r\n", B);
    bad("TE: gzip then chunked (not decoded)", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", http::ERR_NOT_IMPLEMENTED);
    // Not complete yet
    bad("no end of the head", "GET / HTTP/1.1\r\nHost: a\r\n", http::NEED_MORE);
    bad("half a CRLF", "GET / HTTP/1.1\r\nHost: a\r\n\r", http::NEED_MORE);
    bad("half a request line", "GET / HT", http::NEED_MORE);
    bad("nothing", "", http::NEED_MORE);
}

fn limits() {
    let lim = http::default_limits();
    // A request line past max_line: 414, complete or not.
    var long: u8[>..] = [];
    long.append("GET /");
    for i in lim.max_line { long.push('a'); }
    let h1, n1 = http::parse_request(long, lim);
    check("request line past the limit, incomplete: 414", n1 == http::ERR_URI_TOO_LONG);
    long.append(" HTTP/1.1\r\nHost: a\r\n\r\n");
    let h2, n2 = http::parse_request(long, lim);
    check("request line past the limit: 414", n2 == http::ERR_URI_TOO_LONG);
    // Fields past max_head, complete or not: 431.
    var big: u8[>..] = [];
    big.append("GET / HTTP/1.1\r\nHost: a\r\n");
    while big.len <= lim.max_head { big.append("X-Filler: 0123456789012345678901234567890123456789\r\n"); }
    let h3, n3 = http::parse_request(big, lim);
    check("fields past the limit, incomplete: 431", n3 == http::ERR_FIELDS_TOO_LARGE);
    big.append("\r\n");
    let h4, n4 = http::parse_request(big, lim);
    check("fields past the limit: 431", n4 == http::ERR_FIELDS_TOO_LARGE);
    // More field lines than max_fields: 431.
    var many: u8[>..] = [];
    many.append("GET / HTTP/1.1\r\nHost: a\r\n");
    for i in lim.max_fields { many.append("X: y\r\n"); }
    many.append("\r\n");
    let h5, n5 = http::parse_request(many, lim);
    check("more fields than the limit: 431", n5 == http::ERR_FIELDS_TOO_LARGE);
    // Exactly at the limit of fields: taken.
    var at: u8[>..] = [];
    at.append("GET / HTTP/1.1\r\nHost: a\r\n");
    for i in lim.max_fields - 1 { at.append("X: y\r\n"); }
    at.append("\r\n");
    let h6, n6 = http::parse_request(at, lim);
    check("as many fields as the limit: taken", n6 == at.len && h6.fields.len == lim.max_fields);
}

// Every prefix of a valid request needs more; the whole is taken, with
// the bytes after it left for the next.
fn incremental() {
    let lim = http::default_limits();
    let m = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n";
    var all_more = true;
    for k in m.len {
        let h, n = http::parse_request(m[..k], lim);
        if n != http::NEED_MORE { all_more = false; print("      prefix ", k, ": ", n); }
    }
    check("every prefix needs more", all_more);
    var two: u8[>..] = [];
    two.append(m);
    two.append("ok");
    two.append("GET / HTTP/1.1\r\n");
    let h, n = http::parse_request(two, lim);
    check("the head's length", n == m.len && h.len == m.len);
    check("the fields", h.fields.len == 3 && two[h.fields[0].value.pos..h.fields[0].value.end] == "example.com");
    let v, found = http::get(two, h, "CONTENT-LENGTH");
    check("get, any case", found && two[v.pos..v.end] == "2");
    check("keep-alive", http::keep_alive(two, h));
}

fn connection() {
    let lim = http::default_limits();
    let cases = [
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Close\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nConnection: close\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
        "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: closed\r\n\r\n",
    ];
    let want = [true, false, false, false, false, true, true];
    for i in cases.len {
        let h, n = http::parse_request(cases[i], lim);
        check("keep_alive", n > 0 && http::keep_alive(cases[i], h) == want[i]);
    }
}

fn response(m: const u8[:], head_req: bool, connect_req: bool) -> i64, http::Framing, http::Head {
    let lim = http::default_limits();
    var none = http::Framing { kind: http::BODY_NONE, length: 0 };
    let h, n = http::parse_response(m, lim);
    if n <= 0 { return n, none, h; }
    let fr, e = http::response_framing(m, h, head_req, connect_req);
    if e != 0 { return e, none, h; }
    return 1, fr, h;
}

fn responses() {
    let r1, f1, h1 = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", false, false);
    check("200 with a length", r1 == 1 && f1.kind == http::BODY_LENGTH && f1.length == 3 && h1.status == 200);
    let r2, f2, h2 = response("HTTP/1.1 200 OK\r\n\r\n", false, false);
    check("200 to the close", r2 == 1 && f2.kind == http::BODY_CLOSE);
    let r3, f3, h3 = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", true, false);
    check("after HEAD, no body", r3 == 1 && f3.kind == http::BODY_NONE);
    let r4, f4, h4 = response("HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n", false, false);
    check("204, no body", r4 == 1 && f4.kind == http::BODY_NONE);
    let r5, f5, h5 = response("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", false, false);
    check("304, no body", r5 == 1 && f5.kind == http::BODY_NONE);
    let r6, f6, h6 = response("HTTP/1.1 100 Continue\r\n\r\n", false, false);
    check("100, no body", r6 == 1 && f6.kind == http::BODY_NONE && h6.status == 100);
    let r7, f7, h7 = response("HTTP/1.1 200 Connection established\r\n\r\n", false, true);
    check("2xx to CONNECT: a tunnel", r7 == 1 && f7.kind == http::BODY_TUNNEL);
    let r8, f8, h8 = response("HTTP/1.1 407 Proxy Auth\r\nContent-Length: 0\r\n\r\n", false, true);
    check("4xx to CONNECT: no tunnel", r8 == 1 && f8.kind == http::BODY_NONE);
    let r9, f9, h9 = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false, false);
    check("chunked", r9 == 1 && f9.kind == http::BODY_CHUNKED);
    let r10, f10, h10 = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", false, false);
    check("chunked not final: to the close", r10 == 1 && f10.kind == http::BODY_CLOSE);
    let r11, f11, h11 = response("HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", false, false);
    check("no reason phrase", r11 == 1 && h11.status == 200);
    let r12, f12, h12 = response("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n", false, false);
    check("an empty reason phrase", r12 == 1);
    let G = http::ERR_BAD_GATEWAY;
    let r13, f13, h13 = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", false, false);
    check("both TE and CL: refused", r13 == G);
    let r14, f14, h14 = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", false, false);
    check("two lengths: refused", r14 == G);
    let r15, f15, h15 = response("HTTP/1.1 99 Low\r\n\r\n", false, false);
    check("status below 100: refused", r15 == G);
    let r16, f16, h16 = response("HTTP/1.1 2000 OK\r\n\r\n", false, false);
    check("four-digit status: refused", r16 == G);
    let r17, f17, h17 = response("HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", false, false);
    check("bare LF: refused", r17 == G);
    let r18, f18, h18 = response("HTTP/2 200 OK\r\n\r\n", false, false);
    check("HTTP/2 status line: refused", r18 == G);
    let r19, f19, h19 = response("HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n", false, false);
    check("obs-fold: refused", r19 == G);
    let r20, f20, h20 = response("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false, false);
    check("TE in HTTP/1.0: refused", r20 == G);
    let r21, f21, h21 = response("HTTP/1.1 200 OK\r\nContent-Length: 1", false, false);
    check("incomplete", r21 == http::NEED_MORE);
}

// A chunked body fed whole and fed one byte at a time: the same data,
// trailer and length taken.
fn chunked_case(what: const u8[:], m: const u8[:], want_body: const u8[:], want_trailer: const u8[:], want_used: i64) {
    let lim = http::default_limits();
    var d = http::chunked_decoder();
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    let n = http::chunked_feed(d, lim, m, body, trailer);
    check(what, n == want_used && http::chunked_done(d) && body == want_body && trailer == want_trailer);
    if n != want_used || body != want_body || trailer != want_trailer { print("      got ", n, " [", body, "] [", trailer, "]"); }
    var d1 = http::chunked_decoder();
    var body1: u8[>..] = [];
    var trailer1: u8[>..] = [];
    var used = 0;
    var i = 0;
    while i < m.len && !http::chunked_done(d1) {
        let k = http::chunked_feed(d1, lim, m[i..i + 1], body1, trailer1);
        if k < 0 { used = k; break; }
        used += k;
        i++;
    }
    check(what, used == want_used && body1 == want_body && trailer1 == want_trailer);
}

fn chunked_bad(what: const u8[:], m: const u8[:], want: i64) {
    let lim = http::default_limits();
    var d = http::chunked_decoder();
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    let n = http::chunked_feed(d, lim, m, body, trailer);
    check(what, n == want);
    if n != want { print("      got ", n); }
}

fn chunked() {
    let m1 = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    chunked_case("two chunks", m1, "hello world", "", m1.len);
    let m2 = "a\r\n0123456789\r\nA\r\nabcdefghij\r\n0\r\n\r\nGET";
    chunked_case("hex sizes, either case, and what follows", m2, "0123456789abcdefghij", "", m2.len - 3);
    let m3 = "3;name=value;flag\r\nabc\r\n0;last=\"q \\\" s\"\r\n\r\n";
    chunked_case("extensions", m3, "abc", "", m3.len);
    let m4 = "3 ; a = b \r\nabc\r\n0\r\n\r\n";
    chunked_case("whitespace in extensions (BWS)", m4, "abc", "", m4.len);
    let m5 = "1\r\nx\r\n0\r\nExpires: never\r\nX-Sum:  abc \r\n\r\n";
    chunked_case("a trailer", m5, "x", "Expires: never\r\nX-Sum:  abc \r\n", m5.len);
    let m6 = "000000000000003\r\nabc\r\n0\r\n\r\n";
    chunked_case("leading zeros in a size", m6, "abc", "", m6.len);
    let m7 = "0\r\n\r\n";
    chunked_case("empty", m7, "", "", m7.len);

    let B = http::ERR_BAD_REQUEST;
    chunked_bad("no size", "\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("a non-hex size", "g\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("a size with 0x", "0x3\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("a negative size", "-3\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("a size of 16 hex digits", "1000000000000000\r\n", B);
    chunked_bad("bare LF after the size", "3\nabc\r\n0\r\n\r\n", B);
    chunked_bad("bare LF after the data", "3\r\nabc\n0\r\n\r\n", B);
    chunked_bad("data longer than its size", "3\r\nabcd\r\n0\r\n\r\n", B);
    chunked_bad("data shorter than its size", "3\r\nab\r\n0\r\n\r\n", B);
    chunked_bad("another byte where the CR after the data goes", "3\r\nabcX\n0\r\n\r\n", B);
    chunked_bad("another byte where the CR after the size goes", "3X\nabc\r\n0\r\n\r\n", B);
    chunked_bad("an extension without a name", "3;=v\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("an extension name with a non-token byte", "3;a(b\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("an unterminated quoted value", "3;a=\"b\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("a control byte in an extension", "3;a=b\x01\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("junk after the size", "3x\r\nabc\r\n0\r\n\r\n", B);
    chunked_bad("an obs-fold in the trailer", "0\r\nA: b\r\n c\r\n\r\n", B);
    chunked_bad("a trailer line without a colon", "0\r\nnocolon\r\n\r\n", B);
    chunked_bad("a space before a trailer colon", "0\r\nA : b\r\n\r\n", B);
    chunked_bad("bare LF in the trailer", "0\r\nA: b\n\r\n", B);
    chunked_bad("bare LF to end", "0\r\n\n", B);
    var long_ext: u8[>..] = [];
    long_ext.append("3;a=");
    for i in http::default_limits().max_chunk_ext { long_ext.push('x'); }
    long_ext.append("\r\nabc\r\n0\r\n\r\n");
    chunked_bad("extensions past the limit", long_ext, B);
    var long_trailer: u8[>..] = [];
    long_trailer.append("0\r\nX: ");
    for i in http::default_limits().max_trailer { long_trailer.push('x'); }
    long_trailer.append("\r\n\r\n");
    chunked_bad("a trailer past the limit", long_trailer, http::ERR_FIELDS_TOO_LARGE);

    // Not complete: everything taken, not done.
    let lim = http::default_limits();
    var d = http::chunked_decoder();
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    let n = http::chunked_feed(d, lim, "5\r\nhel", body, trailer);
    check("a part of a chunk", n == 6 && body == "hel" && !http::chunked_done(d));
    let n2 = http::chunked_feed(d, lim, "lo\r\n0\r\n\r\n", body, trailer);
    check("the rest", n2 == 9 && body == "hello" && http::chunked_done(d));
}

fn writing() {
    var f: u8[>..] = [];
    check("add Host", http::add_field(f, "Host", "example.com"));
    check("add a value with inner spaces", http::add_field(f, "X-A", "a b\tc"));
    check("refuse a name with a space", !http::add_field(f, "X A", "v"));
    check("refuse a name with a colon", !http::add_field(f, "X:A", "v"));
    check("refuse a CRLF in a value", !http::add_field(f, "X", "a\r\nInjected: 1"));
    check("refuse a bare LF in a value", !http::add_field(f, "X", "a\nb"));
    check("refuse a NUL in a value", !http::add_field(f, "X", "a\x00b"));
    check("refuse leading whitespace", !http::add_field(f, "X", " a"));
    check("refuse trailing whitespace", !http::add_field(f, "X", "a "));
    check("an empty name refused", !http::add_field(f, "", "a"));
    http::add_content_length(f, 5);
    var out: u8[>..] = [];
    check("write a request", http::write_request_head(out, "POST", "/p?q=1", f));
    out.append("hello");
    check("request bytes", out == "POST /p?q=1 HTTP/1.1\r\nHost: example.com\r\nX-A: a b\tc\r\nContent-Length: 5\r\n\r\nhello");
    let lim = http::default_limits();
    let h, n = http::parse_request(out, lim);
    let fr, e = http::request_framing(out, h);
    check("what is written parses back", n > 0 && http::check_request(out, h) == 0 && e == 0 &&
          fr.kind == http::BODY_LENGTH && fr.length == 5 && out[n..] == "hello");
    var bad_out: u8[>..] = [];
    check("refuse a target with a space", !http::write_request_head(bad_out, "GET", "/a b", ""));
    check("refuse a target with CRLF", !http::write_request_head(bad_out, "GET", "/a\r\nX: y", ""));
    check("refuse a method that is no token", !http::write_request_head(bad_out, "G T", "/", ""));
    check("nothing written when refused", bad_out.len == 0);
    var resp: u8[>..] = [];
    var tf: u8[>..] = [];
    check("add a trailer field", http::add_field(tf, "X-Checksum", "abc"));
    check("write a response", http::write_response_head(resp, 200, "Transfer-Encoding: chunked\r\n"));
    http::write_chunk(resp, "hello ");
    http::write_chunk(resp, "");
    http::write_chunk(resp, "world, this chunk is long enough for two hex digits");
    http::write_last_chunk(resp, tf);
    let rh, rn = http::parse_response(resp, lim);
    let rf, re = http::response_framing(resp, rh, false, false);
    check("the response parses back", rn > 0 && rh.status == 200 && re == 0 && rf.kind == http::BODY_CHUNKED &&
          resp[rh.reason.pos..rh.reason.end] == "OK");
    var d = http::chunked_decoder();
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    let used = http::chunked_feed(d, lim, resp[rn..], body, trailer);
    check("the chunked body decodes back", used == resp.len - rn && http::chunked_done(d) &&
          body == "hello world, this chunk is long enough for two hex digits" && trailer == "X-Checksum: abc\r\n");
    check("reason phrases", http::reason_phrase(404) == "Not Found" && http::reason_phrase(431) == "Request Header Fields Too Large" &&
          http::reason_phrase(299) == "");
}

fn main() {
    requests();
    limits();
    incremental();
    connection();
    responses();
    chunked();
    writing();
    print("h1: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}

// HTTP/1.1 connections: the server's ordering of pipelined requests,
// bodies, errors and their answers, HTTP/1.0, HEAD, 204 and 304, answering
// before a body is read, 100-continue; the client's framings, interim
// responses, tunnels and the close; and a client and a server talking to
// each other a byte at a time.

import std;
import http from "..";
import http.conn1;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 30 { print("FAIL ", what); } }
}

// A server fed `input`: the events in order, as letters (R request, B body,
// E end, W waiting, N need more, X error), and the request targets.
struct Run { events: u8[..64], targets: u8[..512] }

fn letter(k: u8) -> u8 {
    if k == http::EV_REQUEST { return 'R'; }
    if k == http::EV_BODY { return 'B'; }
    if k == http::EV_END { return 'E'; }
    if k == http::EV_WAIT { return 'W'; }
    if k == http::EV_NEED_MORE { return 'N'; }
    return 'X';
}

// Reads until the server needs more, waits or fails.
fn drain(c: http::ServerConn&, buf: u8[>..]&, body: u8[>..]&, trailer: u8[>..]&, out: u8[>..]&, r: Run&) {
    loop {
        let ev, h = http::server_read(c, buf, body, trailer, out);
        if r.events.len < r.events.cap { r.events.push(letter(ev.kind)); }
        if ev.kind == http::EV_REQUEST {
            for k in h.target.pos..h.target.end { if r.targets.len < r.targets.cap { r.targets.push(buf[k]); } }
            if r.targets.len < r.targets.cap { r.targets.push(' '); }
        }
        drop(buf, ev.used);
        if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT || ev.kind == http::EV_ERROR { return; }
    }
}

fn new_run() -> Run { Run { events: [], targets: [] } }

// Drops the first n bytes, as a caller does with what an event used.
fn drop(buf: u8[>..]&, n: i64) {
    var rest: u8[>..] = [];
    rest.append(buf[n..]);
    buf.clear();
    buf.append(rest);
}

fn pipelining() {
    var c = http::server_conn(http::server_options());
    var buf: u8[>..] = [];
    buf.append("GET /one HTTP/1.1\r\nHost: a\r\n\r\nGET /two HTTP/1.1\r\nHost: a\r\n\r\n");
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var r = new_run();
    drain(c, buf, body, trailer, out, r);
    check("the first request, then waiting", r.events == "RW" && r.targets == "/one ");
    check("the second not read yet", buf == "GET /two HTTP/1.1\r\nHost: a\r\n\r\n");
    check("respond", http::server_respond(c, 200, "", 3, out) && http::server_body(c, "one", out) && http::server_end(c, "", out));
    check("first response", out == "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none");
    check("still open", !http::closing(c));
    var r2 = new_run();
    drain(c, buf, body, trailer, out, r2);
    check("the second request after the first response", r2.events == "RW" && r2.targets == "/two ");
    out.clear();
    check("a second response", http::server_respond(c, 404, "", 0, out) && http::server_end(c, "", out));
    check("its bytes", out == "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    var r3 = new_run();
    drain(c, buf, body, trailer, out, r3);
    check("then nothing", r3.events == "N" && !http::closing(c));
    check("no second respond to one request", !http::server_respond(c, 200, "", 0, out));
}

fn bodies() {
    // A length, arriving in pieces.
    var c = http::server_conn(http::server_options());
    var buf: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    buf.append("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nhel");
    var r = new_run();
    drain(c, buf, body, trailer, out, r);
    check("a head and part of the body", r.events == "RBN" && body == "hel");
    buf.append("lo worldGET");
    var r2 = new_run();
    drain(c, buf, body, trailer, out, r2);
    check("the rest of the body, the next request's bytes left", r2.events == "EW" && body == "hello worl" && buf == "dGET");
    // That was 10 bytes: "hello worl"; the 'd' begins what follows.
    // Chunked with a trailer.
    var c2 = http::server_conn(http::server_options());
    var b2: u8[>..] = [];
    b2.append("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\n");
    var body2: u8[>..] = [];
    var tr2: u8[>..] = [];
    var r3 = new_run();
    drain(c2, b2, body2, tr2, out, r3);
    check("a chunked body with a trailer", r3.events == "REW" && body2 == "wikipedia" && tr2 == "X-T: 1\r\n" && b2.len == 0);
}

fn errors() {
    let cases = [
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: a\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    ];
    let want = [400, 400, 505, 501, 413, 400];
    for i in cases.len {
        var c = http::server_conn(http::server_options());
        var buf: u8[>..] = [];
        buf.append(cases[i]);
        var body: u8[>..] = [];
        var trailer: u8[>..] = [];
        var out: u8[>..] = [];
        var ev = http::event(http::EV_NEED_MORE, 0);
        loop {
            let e, h = http::server_read(c, buf, body, trailer, out);
            ev = e;
            drop(buf, e.used);
            if e.kind != http::EV_REQUEST && e.kind != http::EV_BODY { break; }
        }
        var expect: u8[>..] = [];
        expect.append("HTTP/1.1 ");
        format(expect, want[i]);
        check("error status", ev.kind == http::EV_ERROR && ev.status == want[i] && http::closing(c));
        check("error answer", starts_with(out, expect) && find(out, "Connection: close\r\n") > 0 && ends_with(out, "\r\n\r\n"));
        let e2, h2 = http::server_read(c, "GET / HTTP/1.1\r\nHost: a\r\n\r\n", body, trailer, out);
        check("nothing read after an error", e2.kind == http::EV_ERROR);
    }
    // A chunked body past max_body.
    var opt = http::server_options();
    opt.max_body = 8;
    var c = http::server_conn(opt);
    var buf: u8[>..] = [];
    buf.append("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n");
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var r = new_run();
    drain(c, buf, body, trailer, out, r);
    check("a chunked body past the limit: 413", r.events == "RX" && starts_with(out, "HTTP/1.1 413 ") && http::closing(c));
}

fn respond(c: http::ServerConn&, req: const u8[:], status: i64, length: i64, data: const u8[:]) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.append(req);
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var r = new_run();
    drain(c, buf, body, trailer, out, r);
    http::server_respond(c, status, "", length, out);
    http::server_body(c, data, out);
    http::server_end(c, "", out);
    return out;
}

fn versions_and_kinds() {
    var c = http::server_conn(http::server_options());
    let o1 = respond(c, "GET / HTTP/1.0\r\n\r\n", 200, 2, "hi");
    check("HTTP/1.0: Connection: close", o1 == "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi" && http::closing(c));
    var c2 = http::server_conn(http::server_options());
    let o2 = respond(c2, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", 200, 2, "hi");
    check("HTTP/1.0 with keep-alive", o2 == "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi" && !http::closing(c2));
    var c3 = http::server_conn(http::server_options());
    let o3 = respond(c3, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", 200, -1, "stream");
    check("HTTP/1.0 without a length: to the close", o3 == "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstream" && http::closing(c3));
    var c4 = http::server_conn(http::server_options());
    let o4 = respond(c4, "GET / HTTP/1.1\r\nHost: a\r\n\r\n", 200, -1, "stream");
    check("HTTP/1.1 without a length: chunked", o4 == "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nstream\r\n0\r\n\r\n" && !http::closing(c4));
    var c5 = http::server_conn(http::server_options());
    let o5 = respond(c5, "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n", 200, 5, "");
    check("HEAD: the length, no body", o5 == "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" && !http::closing(c5));
    var out: u8[>..] = [];
    check("HEAD: body data refused", !http::server_body(c5, "x", out));
    var c6 = http::server_conn(http::server_options());
    let o6 = respond(c6, "DELETE /x HTTP/1.1\r\nHost: a\r\n\r\n", 204, 0, "");
    check("204: no length", o6 == "HTTP/1.1 204 No Content\r\n\r\n");
    var c7 = http::server_conn(http::server_options());
    let o7 = respond(c7, "GET / HTTP/1.1\r\nHost: a\r\n\r\n", 304, -1, "");
    check("304: no length", o7 == "HTTP/1.1 304 Not Modified\r\n\r\n" && !http::closing(c7));
    var c8 = http::server_conn(http::server_options());
    let o8 = respond(c8, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", 200, 0, "");
    check("Connection: close from the client", o8 == "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" && http::closing(c8));
    // Too much body for the length, and too little.
    var c9 = http::server_conn(http::server_options());
    var b9: u8[>..] = [];
    b9.append("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var o9: u8[>..] = [];
    var r = new_run();
    drain(c9, b9, body, trailer, o9, r);
    http::server_respond(c9, 200, "", 3, o9);
    check("more than the length: refused", !http::server_body(c9, "four", o9));
    check("less than the length: the end fails", http::server_body(c9, "ab", o9) && !http::server_end(c9, "", o9) && http::closing(c9));
    var c10 = http::server_conn(http::server_options());
    var b10: u8[>..] = [];
    b10.append("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    var r10 = new_run();
    drain(c10, b10, body, trailer, o9, r10);
    check("no 1xx through respond", !http::server_respond(c10, 100, "", 0, o9));
}

fn early_answer_and_continue() {
    // A response before the body is read closes the connection.
    var c = http::server_conn(http::server_options());
    var buf: u8[>..] = [];
    buf.append("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nabc");
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var r = new_run();
    drain(c, buf, body, trailer, out, r);
    check("a body begun", r.events == "RBN");
    check("an early answer", http::server_respond(c, 413, "", 0, out) && http::server_end(c, "", out));
    check("then closing", http::closing(c) && find(out, "Connection: close") < 0);
    // Expect: 100-continue.
    var c2 = http::server_conn(http::server_options());
    var b2: u8[>..] = [];
    b2.append("PUT /f HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n");
    var o2: u8[>..] = [];
    let ev, h = http::server_read(c2, b2, body, trailer, o2);
    check("Expect: 100-continue seen", ev.kind == http::EV_REQUEST && ev.continue_expected);
    http::server_continue(c2, o2);
    http::server_continue(c2, o2);
    check("one 100 Continue", o2 == "HTTP/1.1 100 Continue\r\n\r\n");
    var c3 = http::server_conn(http::server_options());
    let ev3, h3 = http::server_read(c3, "GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n", body, trailer, o2);
    check("no 100-continue for a request without a body", ev3.kind == http::EV_REQUEST && !ev3.continue_expected);
    var c4 = http::server_conn(http::server_options());
    let ev4, h4 = http::server_read(c4, "PUT /f HTTP/1.0\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n", body, trailer, o2);
    check("no 100-continue for HTTP/1.0", ev4.kind == http::EV_REQUEST && !ev4.continue_expected);
}

// A client reading `input` after sending `method`: the events, and the body.
fn client_case(method: const u8[:], input: const u8[:], eof: bool) -> u8[>..], u8[>..], http::ClientConn {
    var c = http::client_conn();
    var req: u8[>..] = [];
    http::client_request(c, method, if method == "CONNECT" { "a:443" } else { "/" }, "a", "", 0, req);
    var buf: u8[>..] = [];
    buf.append(input);
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var evs: u8[>..] = [];
    loop {
        let ev, h = http::client_read(c, buf, body, trailer);
        if ev.kind == http::EV_RESPONSE { evs.push('S'); evs.push(('0' + h.status / 100) as! u8); }
        else { evs.push(letter(ev.kind)); }
        drop(buf, ev.used);
        if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_ERROR || ev.kind == http::EV_END { break; }
    }
    if eof {
        let e = http::client_eof(c);
        evs.push(letter(e.kind));
    }
    return evs, body, c;
}

fn client() {
    let e1, b1, c1 = client_case("GET", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false);
    check("client: a length", e1 == "S2E" && b1 == "hello" && http::client_idle(c1));
    let e2, b2, c2 = client_case("GET", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", false);
    check("client: interim responses, then chunked", e2 == "S1S1S2E" && b2 == "abc" && http::client_idle(c2));
    let e3, b3, c3 = client_case("HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", false);
    check("client: HEAD's response has no body", e3 == "S2N" && b3.len == 0 && http::client_idle(c3));
    let e4, b4, c4 = client_case("GET", "HTTP/1.1 200 OK\r\n\r\nto the close", true);
    check("client: a body to the close", e4 == "S2BNE" && b4 == "to the close" && http::client_closed(c4));
    let e5, b5, c5 = client_case("GET", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", true);
    check("client: cut short", e5 == "S2BNX");
    let e6, b6, c6 = client_case("CONNECT", "HTTP/1.1 200 OK\r\n\r\nTLS bytes", false);
    check("client: a CONNECT tunnel", e6 == "S2N" && b6.len == 0);
    let e7, b7, c7 = client_case("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", false);
    check("client: Connection: close", e7 == "S2E" && http::client_closed(c7));
    let e8, b8, c8 = client_case("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok", false);
    check("client: two lengths refused", e8 == "X");
    let e9, b9, c9 = client_case("GET", "HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", false);
    check("client: 204, then bytes no request asked for: an error", e9 == "S2X" && http::client_closed(c9));
    var c10 = http::client_conn();
    var o: u8[>..] = [];
    check("client: a request", http::client_request(c10, "POST", "/p", "example.com:8080", "Accept: */*\r\n", 2, o));
    check("client: its bytes", o == "POST /p HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\nContent-Length: 2\r\n\r\n");
    check("client: one request at a time", !http::client_request(c10, "GET", "/", "a", "", 0, o));
    var c11 = http::client_conn();
    check("client: a Host with CRLF refused", !http::client_request(c11, "GET", "/", "a\r\nX: y", "", 0, o));
    var c12 = http::client_conn();
    var o12: u8[>..] = [];
    check("client: GET without a body has no length", http::client_request(c12, "GET", "/", "a", "", 0, o12) &&
          o12 == "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let ev13, h13 = http::client_read(c1, "HTTP/1.1 200 OK\r\n\r\n", b1, b1);
    check("client: a response nobody asked for", ev13.kind == http::EV_ERROR && http::client_closed(c1));
}

// A client and a server, each request and response delivered one byte at
// a time each way.
fn talk() {
    var cl = http::client_conn();
    var sv = http::server_conn(http::server_options());
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var sbuf: u8[>..] = [];
    var cbuf: u8[>..] = [];
    var sbody: u8[>..] = [];
    var cbody: u8[>..] = [];
    var trailer: u8[>..] = [];
    var all_ok = true;
    for round in 3 {
        var f: u8[>..] = [];
        http::add_field(f, "X-Round", "r");
        all_ok = all_ok && http::client_request(cl, "POST", "/echo", "localhost", f, -1, to_server);
        http::write_chunk(to_server, "ping ");
        http::write_chunk(to_server, "pong");
        http::write_last_chunk(to_server, "");
        sbody.clear();
        cbody.clear();
        var got_request = false;
        var answered = false;
        var done = false;
        var steps = 0;
        while !done && steps < 10000 {
            steps++;
            if to_server.len > 0 { sbuf.push(to_server[0]); drop(to_server, 1); }
            loop {
                let ev, h = http::server_read(sv, sbuf, sbody, trailer, to_client);
                if ev.kind == http::EV_REQUEST {
                    got_request = sbuf[h.target.pos..h.target.end] == "/echo";
                    let v, found = http::get(sbuf, h, "x-round");
                    got_request = got_request && found;
                }
                drop(sbuf, ev.used);
                if ev.kind == http::EV_END && !answered {
                    http::server_respond(sv, 200, "Content-Type: text/plain\r\n", -1, to_client);
                    http::server_body(sv, sbody, to_client);
                    http::server_end(sv, "X-Done: yes\r\n", to_client);
                    answered = true;
                }
                if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT || ev.kind == http::EV_ERROR { break; }
            }
            if to_client.len > 0 { cbuf.push(to_client[0]); drop(to_client, 1); }
            loop {
                let ev, h = http::client_read(cl, cbuf, cbody, trailer);
                drop(cbuf, ev.used);
                if ev.kind == http::EV_END { done = true; break; }
                if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_ERROR { break; }
            }
        }
        all_ok = all_ok && done && got_request && cbody == "ping pong" && http::client_idle(cl) && !http::closing(sv);
    }
    check("three exchanges, a byte at a time", all_ok);
    check("the last trailer", trailer == "X-Done: yes\r\nX-Done: yes\r\nX-Done: yes\r\n");
}

fn main() {
    pipelining();
    bodies();
    errors();
    versions_and_kinds();
    early_answer_and_continue();
    client();
    talk();
    print("conn1: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}

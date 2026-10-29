// http.conn1: HTTP/1.1 connections without I/O, server and client. The
// caller keeps the bytes that have arrived in a buffer of its own and asks
// the connection what they hold, one event at a time:
//
//   var c = http::server_conn(http::server_options());
//   loop {
//       let ev, h = http::server_read(c, buf, body, trailer);
//       // EV_REQUEST: h is the head, its spans into buf (read them now)
//       // EV_BODY: data appended to body; EV_END: the request is complete
//       // EV_NEED_MORE: read more into buf; EV_ERROR: send out, then close
//       buf = buf[ev.used..]        // the caller drops what was used
//   }
//   http::server_respond(c, 200, fields, 5, out);    // or -1: chunked
//   http::server_body(c, "hello", out);
//   http::server_end(c, "", out);                   // then: closing(c)?
//
// The connection answers requests in order: the next request is not read
// until the response to this one has ended. A response that ends before
// its request's body was all read closes the connection, as do HTTP/1.0
// without keep-alive, Connection: close either way, and every error.

namespace http;

import std;
import http;
import h1;

let EV_NEED_MORE: u8 = 0;
let EV_REQUEST: u8 = 1;        // a server's: a request head
let EV_RESPONSE: u8 = 2;       // a client's: a response head (1xx ones too)
let EV_BODY: u8 = 3;           // body data appended
let EV_END: u8 = 4;            // the body (or a message without one) is complete
let EV_ERROR: u8 = 5;          // the connection failed; for a server, out holds the answer
let EV_WAIT: u8 = 6;           // a server's: a request is being answered, nothing more is read

struct Event {
    kind: u8,
    used: i64,                  // bytes of the buffer this event took
    status: i64,                // EV_ERROR: the status (a server's answer), or 0
    continue_expected: bool,    // EV_REQUEST: Expect: 100-continue
}

fn event(kind: u8, used: i64) -> Event { Event { kind: kind, used: used, status: 0, continue_expected: false } }

// --- Server ----------------------------------------------------------------

struct ServerOptions {
    lim: Limits,
    max_body: i64,              // bytes of a request body; past it, 413
}

fn server_options() -> ServerOptions { ServerOptions { lim: default_limits(), max_body: 1 << 24 } }

let SV_HEAD: u8 = 1;            // reading a request head
let SV_BODY: u8 = 2;            // reading its body
let SV_ANSWER: u8 = 3;          // the request is read; its response is not done
let SV_CLOSING: u8 = 4;         // no more requests: send what is out, then close

struct ServerConn {
    opt: ServerOptions,
    state: u8,
    fr: Framing,
    ck: Chunked,
    remaining: i64,             // BODY_LENGTH: bytes left
    body_read: i64,
    request_done: bool,         // its body all read
    keep: bool,                 // the request allows the connection to stay
    head: bool,                 // the request was HEAD
    continue_expected: bool, continue_sent: bool,
    // The response
    responding: bool,           // a head has been sent
    resp_chunked: bool,
    resp_close_delimited: bool, // to an HTTP/1.0 client, without a length
    resp_remaining: i64,        // a length's bytes still to send, or -1
    resp_body: bool,            // the response may have a body
    minor: u8,
    requests: i64,
}

fn server_conn(opt: ServerOptions) -> ServerConn {
    ServerConn {
        opt: opt, state: SV_HEAD, fr: Framing { kind: BODY_NONE, length: 0 }, ck: chunked_decoder(),
        remaining: 0, body_read: 0, request_done: false, keep: true, head: false,
        continue_expected: false, continue_sent: false,
        responding: false, resp_chunked: false, resp_close_delimited: false, resp_remaining: -1, resp_body: true,
        minor: 1, requests: 0,
    }
}

fn closing(c: const ServerConn&) -> bool { c.state == SV_CLOSING }

// Whether the request being answered has been read whole: after a
// REQUEST event without a body, or after END.
fn request_complete(c: const ServerConn&) -> bool { c.request_done && c.state != SV_HEAD }

// An error answer, then no more requests.
fn server_fail(c: ServerConn&, status: i64, out: u8[>..]&) -> Event {
    var f: u8[>..] = [];
    add_content_length(f, 0);
    f.append("Connection: close\r\n");
    if !c.responding { write_response_head(out, status, f); }
    c.state = SV_CLOSING;
    var ev = event(EV_ERROR, 0);
    ev.status = status;
    return ev;
}

// What the buffer holds next. A REQUEST event's head has spans into `m`,
// valid until the caller drops ev.used bytes; BODY appends to `body` and
// END to `trailer` (a chunked body's trailer fields). An ERROR's answer,
// if the request could not be read, is in `out`.
fn server_read(c: ServerConn&, m: const u8[:], body: u8[>..]&, trailer: u8[>..]&, out: u8[>..]&) -> Event, Head {
    var h = new_head(KIND_REQUEST);
    if c.state == SV_CLOSING { return event(EV_ERROR, 0), h; }
    if c.state == SV_ANSWER { return event(EV_WAIT, 0), h; }
    if c.state == SV_HEAD {
        let hh, n = parse_request(m, c.opt.lim);
        if n == NEED_MORE { return event(EV_NEED_MORE, 0), hh; }
        if n < 0 { return server_fail(c, -n, out), hh; }
        let e = check_request(m, hh);
        if e != 0 { return server_fail(c, -e, out), hh; }
        let fr, ef = request_framing(m, hh);
        if ef != 0 { return server_fail(c, -ef, out), hh; }
        if fr.kind == BODY_LENGTH && fr.length > c.opt.max_body { return server_fail(c, 413, out), hh; }
        c.fr = fr;
        c.ck = chunked_decoder();
        c.remaining = fr.length;
        c.body_read = 0;
        c.minor = hh.minor;
        c.keep = keep_alive(m, hh);
        c.head = m[hh.method.pos..hh.method.end] == "HEAD";
        c.continue_expected = hh.minor >= 1 && has_token(m, hh, "expect", "100-continue") && fr.kind != BODY_NONE;
        c.continue_sent = false;
        c.responding = false;
        c.resp_remaining = -1;
        c.requests++;
        c.request_done = fr.kind == BODY_NONE;
        c.state = if c.request_done { SV_ANSWER } else { SV_BODY };
        var ev = event(EV_REQUEST, n);
        ev.continue_expected = c.continue_expected;
        return ev, hh;
    }
    // SV_BODY
    if c.fr.kind == BODY_LENGTH {
        if m.len == 0 { return event(EV_NEED_MORE, 0), h; }
        let k = if m.len < c.remaining { m.len } else { c.remaining };
        body.append(m[..k]);
        c.remaining -= k;
        if c.remaining > 0 { return event(EV_BODY, k), h; }
        c.request_done = true;
        c.state = if c.state == SV_BODY { SV_ANSWER } else { c.state };
        return event(EV_END, k), h;
    }
    let before = body.len;
    let k = chunked_feed(c.ck, c.opt.lim, m, body, trailer);
    if k < 0 { return server_fail(c, -k, out), h; }
    c.body_read += body.len - before;
    if c.body_read > c.opt.max_body { return server_fail(c, 413, out), h; }
    if chunked_done(c.ck) {
        c.request_done = true;
        c.state = SV_ANSWER;
        return event(EV_END, k), h;
    }
    return event(if k == 0 { EV_NEED_MORE } else { EV_BODY }, k), h;
}

// The interim answer to Expect: 100-continue (RFC 9110 §10.1.1), sent at
// most once and only before the response.
fn server_continue(c: ServerConn&, out: u8[>..]&) {
    if !c.continue_expected || c.continue_sent || c.responding { return; }
    out.append("HTTP/1.1 100 Continue\r\n\r\n");
    c.continue_sent = true;
}

// The response head: `fields` from add_field, without Content-Length,
// Transfer-Encoding or Connection, which this adds. `length` is the
// body's length, or -1 for one sent in chunks (to an HTTP/1.0 client, to
// the close). False if a response was already begun, or for a 1xx (use
// server_continue) or a status out of range.
fn server_respond(c: ServerConn&, status: i64, fields: const u8[:], length: i64, out: u8[>..]&) -> bool {
    if c.responding || c.state == SV_HEAD || status < 200 || status > 999 { return false; }
    if c.state == SV_CLOSING && c.requests == 0 { return false; }
    c.responding = true;
    c.resp_body = !c.head && status != 204 && status != 304;
    // A body still unread when the response is done can only be skipped
    // by reading it; the connection closes instead, as it does if the
    // client sent 100-continue's Expect and got no 100.
    var f: u8[>..] = [];
    f.append(fields);
    c.resp_chunked = false;
    c.resp_close_delimited = false;
    if status != 204 && (status != 304 || length >= 0) {
        if length >= 0 {
            add_content_length(f, length);
        } else if c.minor >= 1 {
            if c.resp_body { f.append("Transfer-Encoding: chunked\r\n"); }
            c.resp_chunked = c.resp_body;
        } else {
            c.resp_close_delimited = c.resp_body;
            c.keep = false;
        }
    }
    c.resp_remaining = if length >= 0 && c.resp_body { length } else { -1 };
    if !c.keep {
        f.append("Connection: close\r\n");
    } else if c.minor == 0 {
        f.append("Connection: keep-alive\r\n");
    }
    write_response_head(out, status, f);
    return true;
}

// Body data of the response; false past its length, or when it has none.
fn server_body(c: ServerConn&, data: const u8[:], out: u8[>..]&) -> bool {
    if !c.responding { return false; }
    if !c.resp_body { return data.len == 0; }
    if c.resp_chunked { write_chunk(out, data); return true; }
    if c.resp_remaining >= 0 {
        if data.len > c.resp_remaining { return false; }
        c.resp_remaining -= data.len;
    }
    out.append(data);
    return true;
}

// The end of the response: a chunked one's last chunk and trailer
// fields. False if a length's bytes are still owed (the connection then
// closes, as the client cannot tell where the response ends otherwise).
// The connection then reads the next request, or is closing.
fn server_end(c: ServerConn&, trailer: const u8[:], out: u8[>..]&) -> bool {
    if !c.responding { return false; }
    var ok = true;
    if c.resp_chunked { write_last_chunk(out, trailer); }
    if c.resp_remaining > 0 { ok = false; }
    c.responding = false;
    if !ok || !c.keep || !c.request_done || c.resp_close_delimited { c.state = SV_CLOSING; }
    else { c.state = SV_HEAD; }
    return ok;
}

// --- Client ----------------------------------------------------------------

let CL_IDLE: u8 = 1;            // no request outstanding
let CL_HEAD: u8 = 2;            // waiting for a response head
let CL_BODY: u8 = 3;            // reading its body
let CL_TUNNEL: u8 = 4;          // a CONNECT's tunnel: the bytes are the caller's
let CL_CLOSED: u8 = 5;

struct ClientConn {
    lim: Limits,
    max_body: i64,
    state: u8,
    head: bool, connect: bool,  // the outstanding request's method
    request_keep: bool,
    keep: bool,
    fr: Framing,
    ck: Chunked,
    remaining: i64,
    body_read: i64,
}

fn client_conn() -> ClientConn {
    ClientConn {
        lim: default_limits(), max_body: 1 << 30, state: CL_IDLE, head: false, connect: false, request_keep: true,
        keep: true, fr: Framing { kind: BODY_NONE, length: 0 }, ck: chunked_decoder(), remaining: 0, body_read: 0,
    }
}

fn client_closed(c: const ClientConn&) -> bool { c.state == CL_CLOSED }
fn client_idle(c: const ClientConn&) -> bool { c.state == CL_IDLE }

// A request head, then the body as the caller sends it: with `length`
// bytes (Content-Length; 0 for none), or -1 for chunks (write_chunk and
// write_last_chunk). `host` is the Host field's value; `fields` from
// add_field, without Host, Content-Length or Transfer-Encoding. False if a
// request is outstanding or the request cannot be written.
fn client_request(c: ClientConn&, method: const u8[:], target: const u8[:], host: const u8[:], fields: const u8[:],
                  length: i64, out: u8[>..]&) -> bool {
    if c.state != CL_IDLE { return false; }
    var f: u8[>..] = [];
    if !add_field(f, "Host", host) { return false; }
    f.append(fields);
    if length > 0 || (length == 0 && (method == "POST" || method == "PUT" || method == "PATCH")) {
        add_content_length(f, length);
    } else if length < 0 {
        f.append("Transfer-Encoding: chunked\r\n");
    }
    if !write_request_head(out, method, target, f) { return false; }
    c.head = method == "HEAD";
    c.connect = method == "CONNECT";
    c.request_keep = !has_close(fields);
    c.state = CL_HEAD;
    return true;
}

fn has_close(fields: const u8[:]) -> bool {
    var close = false;
    each_split(fields, '\n') {
        let line = it;
        let colon = position(line, ':');
        if colon > 0 && eq_fold(line[..colon], "connection") {
            each_split(line[colon + 1..], ',') { if eq_fold(trim_ows(trim_cr(it)), "close") { close = true; } };
        }
    };
    return close;
}

fn trim_cr(s: const u8[:]) -> const u8[:] { if s.len > 0 && s[s.len - 1] == '\r' { s[..s.len - 1] } else { s } }

// What the buffer holds next: RESPONSE (a 1xx one is followed by another
// RESPONSE), BODY, END, NEED_MORE, or ERROR. After END the connection is
// idle for the next request, or closed.
fn client_read(c: ClientConn&, m: const u8[:], body: u8[>..]&, trailer: u8[>..]&) -> Event, Head {
    var h = new_head(KIND_RESPONSE);
    if c.state == CL_CLOSED { return event(EV_ERROR, 0), h; }
    if c.state == CL_IDLE {
        // Bytes no request asked for.
        if m.len > 0 { c.state = CL_CLOSED; return event(EV_ERROR, 0), h; }
        return event(EV_NEED_MORE, 0), h;
    }
    if c.state == CL_TUNNEL { return event(EV_NEED_MORE, 0), h; }
    if c.state == CL_HEAD {
        let hh, n = parse_response(m, c.lim);
        if n == NEED_MORE { return event(EV_NEED_MORE, 0), hh; }
        if n < 0 { c.state = CL_CLOSED; return event(EV_ERROR, 0), hh; }
        if hh.status < 200 && hh.status != 101 {
            return event(EV_RESPONSE, n), hh;       // interim; the final one follows
        }
        let fr, e = response_framing(m, hh, c.head, c.connect);
        if e != 0 { c.state = CL_CLOSED; return event(EV_ERROR, 0), hh; }
        if fr.kind == BODY_LENGTH && fr.length > c.max_body { c.state = CL_CLOSED; return event(EV_ERROR, 0), hh; }
        c.fr = fr;
        c.ck = chunked_decoder();
        c.remaining = fr.length;
        c.body_read = 0;
        c.keep = c.request_keep && keep_alive(m, hh);
        if hh.status == 101 || fr.kind == BODY_TUNNEL {
            c.state = CL_TUNNEL;
        } else if fr.kind == BODY_NONE {
            c.state = if c.keep { CL_IDLE } else { CL_CLOSED };
        } else {
            c.state = CL_BODY;
        }
        return event(EV_RESPONSE, n), hh;
    }
    // CL_BODY
    if c.fr.kind == BODY_CLOSE {
        body.append(m);
        c.body_read += m.len;
        if c.body_read > c.max_body { c.state = CL_CLOSED; return event(EV_ERROR, 0), h; }
        return event(if m.len > 0 { EV_BODY } else { EV_NEED_MORE }, m.len), h;
    }
    if c.fr.kind == BODY_LENGTH {
        if m.len == 0 { return event(EV_NEED_MORE, 0), h; }
        let k = if m.len < c.remaining { m.len } else { c.remaining };
        body.append(m[..k]);
        c.remaining -= k;
        if c.remaining > 0 { return event(EV_BODY, k), h; }
        c.state = if c.keep { CL_IDLE } else { CL_CLOSED };
        return event(EV_END, k), h;
    }
    let before = body.len;
    let k = chunked_feed(c.ck, c.lim, m, body, trailer);
    if k < 0 { c.state = CL_CLOSED; return event(EV_ERROR, 0), h; }
    c.body_read += body.len - before;
    if c.body_read > c.max_body { c.state = CL_CLOSED; return event(EV_ERROR, 0), h; }
    if chunked_done(c.ck) {
        c.state = if c.keep { CL_IDLE } else { CL_CLOSED };
        return event(EV_END, k), h;
    }
    return event(if k == 0 { EV_NEED_MORE } else { EV_BODY }, k), h;
}

// The server closed the connection: the end of a body read to the close,
// or an error if a message was cut short.
fn client_eof(c: ClientConn&) -> Event {
    let was = c.state;
    c.state = CL_CLOSED;
    if was == CL_BODY && c.fr.kind == BODY_CLOSE { return event(EV_END, 0); }
    if was == CL_IDLE || was == CL_TUNNEL { return event(EV_END, 0); }
    return event(EV_ERROR, 0);
}

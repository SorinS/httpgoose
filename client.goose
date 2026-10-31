// http.client: an HTTP/1.1 client that does the I/O, over TCP or TLS
// (tlsgoose), as Go's http.Client and Transport: a pool of connections
// kept open per origin, retrying a request that met a connection the
// server had closed, timeouts, and responses read whole or as a stream.
// Connections go directly, through an HTTP proxy (absolute-form requests,
// or a CONNECT tunnel for https; the proxy itself over TLS too, as Go's
// https proxies), or through SOCKS5 (RFC 1928, with RFC 1929's password).
// Redirects, cookies, authentication and the proxy environment are the
// policy of http.fetch, built on this module.
//
//   var c = http::Client { .. };
//   var r = http::round_trip(c, "GET", u, fields, "");     // u: an http::Url
//   if r.err == 0 {
//       var body: u8[>..] = [];
//       while http::read_body(c, r, body) > 0 {}
//   }
//
// Several responses may be open at once, each on its connection, and read
// in any order. The sockets are in src/httpnet.c, built with programs
// that use this module.

namespace http;

import std;
import os;
import http;
import h1;
import conn1;
import url;
import cookie;
import flate;
import tls from "../tlsgoose.git";
import tls.handshake;
import tls.session;

extern fn httpnet_connect(host: const u8[:], port: i32, timeout_ms: i32) -> i64;
extern fn httpnet_read(fd: i64, buf: u8[:], timeout_ms: i32) -> i64;
extern fn httpnet_write(fd: i64, data: const u8[:], timeout_ms: i32) -> i64;
extern fn httpnet_readable(fd: i64) -> i32;
extern fn httpnet_close(fd: i64);

let NET_EARG: i64 = -1;
let NET_ERESOLVE: i64 = -2;
let NET_ECONNECT: i64 = -3;
let NET_ETIMEOUT: i64 = -4;
let NET_EIO: i64 = -5;

// A Response's errors.
let ERR_NONE: i64 = 0;
let ERR_URL: i64 = 1;               // not an http or https URL with a host
let ERR_RESOLVE: i64 = 2;           // the host name does not resolve
let ERR_CONNECT: i64 = 3;           // refused or unreachable
let ERR_TIMEOUT: i64 = 4;
let ERR_IO: i64 = 5;                // the connection failed (reset, closed early)
let ERR_TLS: i64 = 6;               // the TLS handshake or a record failed
let ERR_PROTOCOL: i64 = 7;          // a response this client cannot read
let ERR_REQUEST: i64 = 8;           // the request cannot be written (a bad method or field)
let ERR_TOO_LARGE: i64 = 9;         // the body passed the client's max_body
let ERR_REDIRECTS: i64 = 10;        // more redirects than max_redirects
let ERR_PROXY: i64 = 11;            // the proxy refused the tunnel, or its answer was not HTTP
let ERR_DECODE: i64 = 12;           // a gzip body that does not decode
let ERR_STATE: i64 = 13;            // a call the response is not ready for (write_body after end_request, say)
let ERR_AUTH: i64 = 14;             // (not returned: a 401 or 407 comes back as the response)

fn client_error_text(e: i64) -> const u8[:] {
    if e == ERR_URL { return "not an http or https URL with a host"; }
    if e == ERR_RESOLVE { return "the host name does not resolve"; }
    if e == ERR_CONNECT { return "the connection was refused or the host is unreachable"; }
    if e == ERR_TIMEOUT { return "timed out"; }
    if e == ERR_IO { return "the connection failed"; }
    if e == ERR_TLS { return "TLS failed"; }
    if e == ERR_PROTOCOL { return "the response is not HTTP/1.x this client can read"; }
    if e == ERR_REQUEST { return "the request cannot be written"; }
    if e == ERR_TOO_LARGE { return "the body is larger than the client takes"; }
    if e == ERR_REDIRECTS { return "too many redirects"; }
    if e == ERR_PROXY { return "the proxy failed"; }
    if e == ERR_DECODE { return "the body's content coding does not decode"; }
    if e == ERR_STATE { return "the request is not in a state for that"; }
    if e == ERR_AUTH { return "the credentials were refused"; }
    return "";
}

struct ClientOptions {
    connect_timeout_ms: i64,        // each connection (0: none); Go's Dialer has 30 s
    read_timeout_ms: i64,           // each read of the response (0: none)
    timeout_ms: i64,                // a whole request: redirects, connections, reading the body (0: none; Go's Client.Timeout)
    max_idle: i64,                  // idle connections kept, in all (0: none, every connection closes)
    max_idle_per_host: i64,         // for one origin (Go's DefaultMaxIdleConnsPerHost: 2)
    max_body: i64,                  // what read_all takes into memory
    max_redirects: i64,             // Go stops after 10
    follow_redirects: bool,
    compression: bool,              // ask for gzip and decode it (Go's !DisableCompression)
    insecure: bool,                 // check no certificate (Go's InsecureSkipVerify)
    cookies: bool,                  // keep cookies in the client's jar and send them (Go's Client.Jar)
    auth: u8,                       // how the client's credentials are sent: AUTH_*
    tls_sessions: i64,              // TLS sessions kept to resume, one per server name (0: none)
    expect_continue_ms: i64,        // with Expect: 100-continue, how long to wait for the 100 before the body goes (Go's ExpectContinueTimeout; 0: no wait)
    user_agent: u8[..256],          // sent unless the request has one; empty: none
}

// How a client's credentials (set_credentials) go to servers: Basic before
// any challenge (as Go sends a URL's userinfo), or only in answer to a 401
// with the scheme it asks for (Digest, or Basic), or Digest only.
let AUTH_BASIC: u8 = 1;
let AUTH_ANY: u8 = 2;
let AUTH_DIGEST: u8 = 3;

fn client_options() -> ClientOptions {
    var o = ClientOptions {
        connect_timeout_ms: 30000, read_timeout_ms: 0, timeout_ms: 0, max_idle: 100, max_idle_per_host: 2,
        max_body: 1 << 30, max_redirects: 10, follow_redirects: true, compression: true, insecure: false,
        cookies: false, auth: AUTH_ANY, tls_sessions: 64, expect_continue_ms: 1000, user_agent: [],
    };
    o.user_agent.append("goose-http-client/1.1");
    return o;
}

// A connection of the pool: in use, idle, or a free slot.
struct PoolConn {
    used: bool,                     // the slot holds a connection
    gen: i64,                       // which connection the slot holds (responses check it is still theirs)
    idle: bool,                     // in the pool, waiting for a request
    fd: i64,
    key: u8[..600],                 // what it reaches: scheme, host, port, and the proxy's
    is_tls: bool,
    reused: bool,                   // it has carried a request before this one
    must_close: bool,               // a request's body was not all sent: closed after its response
    last_used: i64,                 // clock_ns() when it went idle
    server_name: u8[..255],
    sess_sig: u64,                  // the TLS session last put in the cache from it
    outer: i64,                     // the TLS to an https proxy beneath its own (c.outer), or -1
    via_proxy: bool,                // requests go to an HTTP proxy in absolute-form
    hc: ClientConn,
    tc: tls::Conn,
}

// TLS to an https proxy, under a tunnel's own TLS.
struct OuterTls { used: bool, server_name: u8[..255], sess_sig: u64, tc: tls::Conn }

// Where requests go: PROXY_NONE directly, PROXY_URL through one proxy for
// every URL (Go's http.ProxyURL), PROXY_ENV by the environment's
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY (Go's ProxyFromEnvironment).
let PROXY_NONE: u8 = 0;
let PROXY_URL: u8 = 1;
let PROXY_ENV: u8 = 2;

root struct Client {
    opt: ClientOptions = client_options(),
    tlscfg: tls::ClientConfig = tls::client_config("", ""),
    conns: PoolConn[>..] = [],
    outer: OuterTls[>..] = [],
    buf: u8[>..] = [],              // plaintext that has come on connection buf_owner and is not used yet
    buf_owner: i64 = -1,
    store: u8[>..] = [],            // the other connections' input not used yet: records of store_put
    raw: u8[>..] = [],              // a read from the socket
    mid: u8[>..] = [],              // an https proxy's plaintext: the tunnel's TLS records
    wire: u8[>..] = [],             // bytes to send
    wire2: u8[>..] = [],            // the same, through an https proxy's TLS
    deadline: i64 = 0,              // clock_ns() the operation under way must end by, or 0 (its response's)
    gen_seq: i64 = 0,
    inflates: Inflate[>..] = [],    // gzip decoders, one a response that is decoded
    inflate_used: bool[>..] = [],
    jar: Jar = new_jar(),
    psl: Psl = empty_psl(),
    user: u8[>..] = [],             // credentials for servers (set_credentials)
    password: u8[>..] = [],
    bearer: u8[>..] = [],           // a token sent as "Bearer" (set_bearer)
    proxy_mode: u8 = PROXY_NONE,
    proxy_http: u8[>..] = [],       // the proxies' URLs, as the environment or set_proxy gave them
    proxy_https: u8[>..] = [],
    no_proxy: u8[>..] = [],
    proxy_cgi: bool = false,        // REQUEST_METHOD is set: HTTP_PROXY is not used (Go's rule)
    proxy_authz: u8[>..] = [],      // the Proxy-Authorization value to send, if any
    proxy_status: i64 = 0,          // a proxy's answer to CONNECT that was not 2xx
    proxy_fields: u8[>..] = [],     // and its field lines (Proxy-Authenticate)
    pend: u8[>..] = [],             // a request's head and body not sent yet, on connection pend_owner
    pend_owner: i64 = -1,
    sessions: u8[>..] = [],         // the TLS session cache: records of session_put
    digest_base: u8[>..] = [],      // the URL whose 401 the client's Digest answered (http.fetch), empty for none
    digest_params: u8[>..] = [],    // that challenge's params, answered again with digest_nc + 1
    digest_user: u8[>..] = [],
    digest_password: u8[>..] = [],
    digest_nc: i64 = 0,
    session_seq: i64 = 0,
}

// A response, its head and what of the body read_all took. Its parts are
// spans into `data`: the URL it came from, the head's field lines (each
// "Name: value\r\n" as received), the trailer's (after a chunked body),
// and the body.
struct Response {
    err: i64,                       // ERR_NONE, or what went wrong (no response then)
    status: i64,
    minor: u8,                      // HTTP/1.minor
    reason: Span,
    url: Span,
    fields: Span,
    trailer: Span,
    body: Span,
    redirects: i64,                 // redirects followed to get it
    conn: i64,                      // the pool slot its body is read from, -1 when done
    body_done: bool,
    decode: bool,                   // the body is gzip, decoded as it is read (Go's Uncompressed)
    tls_version: u16,               // the connection's TLS version, 0 for none
    tls_resumed: bool,              // its handshake resumed a session
    reused: bool,                   // the connection had carried a request before (Go's GotConnInfo.Reused)
    sending: bool,                  // begin_request's: the body is being sent (write_body, then end_request)
    early: bool,                    // a final response came before the body was all sent: the rest is not sent
    length: i64,                    // the body's length as declared, -1 for chunks
    sent: i64,                      // what of it has gone
    write_err: i64,                 // the error sending it met, if any
    deadline: i64,                  // clock_ns() it must end by (the client's timeout), or 0
    gen: i64,                       // its connection's generation
    inflate: i64,                   // its gzip decoder in c.inflates, or -1
    data: u8[>..],
}

fn empty_response(err: i64) -> Response {
    Response {
        err: err, status: 0, minor: 1, reason: empty_span(), url: empty_span(), fields: empty_span(),
        trailer: empty_span(), body: empty_span(), redirects: 0, conn: -1, body_done: true, decode: false,
        tls_version: 0, tls_resumed: false, reused: false,
        sending: false, early: false, length: 0, sent: 0, write_err: 0, deadline: 0, gen: 0, inflate: -1, data: [],
    }
}

// Every field as empty_response has it.
fn reset_response(r: Response&, err: i64) {
    r.err = err;
    r.status = 0;
    r.minor = 1;
    r.reason = empty_span();
    r.url = empty_span();
    r.fields = empty_span();
    r.trailer = empty_span();
    r.body = empty_span();
    r.redirects = 0;
    r.conn = -1;
    r.body_done = true;
    r.decode = false;
    r.tls_version = 0;
    r.tls_resumed = false;
    r.reused = false;
    r.sending = false;
    r.early = false;
    r.length = 0;
    r.sent = 0;
    r.write_err = 0;
    r.deadline = 0;
    r.gen = 0;
    r.inflate = -1;
    r.data.clear();
}

fn response_part(r: const Response&, s: Span) -> const u8[:] { r.data[s.pos..s.end] }
fn response_body(r: const Response&) -> const u8[:] { response_part(r, r.body) }
fn response_url(r: const Response&) -> const u8[:] { response_part(r, r.url) }
fn response_reason(r: const Response&) -> const u8[:] { response_part(r, r.reason) }
fn response_fields(r: const Response&) -> const u8[:] { response_part(r, r.fields) }
fn response_trailer(r: const Response&) -> const u8[:] { response_part(r, r.trailer) }

// The value of the first field named `name` in a field section of
// "Name: value\r\n" lines.
fn field_value(fields: const u8[:], name: const u8[:]) -> const u8[:], bool {
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        let colon = position(line, ':');
        if colon > 0 && eq_fold(line[..colon], name) { return trim_ows(line[colon + 1..]), true; }
        pos = end + 2;
    }
    return "", false;
}

fn response_header(r: const Response&, name: const u8[:]) -> const u8[:], bool {
    return field_value(response_fields(r), name);
}

// Each value of the fields named `name`, one a line (Set-Cookie's, say),
// as F(value).
fn each_field<F>(fields: const u8[:], name: const u8[:]) {
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        let colon = position(line, ':');
        if colon > 0 && eq_fold(line[..colon], name) { F(trim_ows(line[colon + 1..])); }
        pos = end + 2;
    }
}

// --- Time ------------------------------------------------------------------

// The time a read or write may wait (ms, 0 for ever), within the request's
// deadline and the read timeout; -1 if the deadline has passed.
fn wait_ms(c: const Client&, per_op: i64) -> i64 {
    var t = per_op;
    if c.deadline > 0 {
        let left = (c.deadline - clock_ns()) / 1000000;
        if left <= 0 { return -1; }
        if t == 0 || left < t { t = left; }
    }
    if t > 0x7fffffff { t = 0x7fffffff; }
    return t;
}

fn net_error(n: i64) -> i64 {
    if n == NET_ERESOLVE { return ERR_RESOLVE; }
    if n == NET_ECONNECT { return ERR_CONNECT; }
    if n == NET_ETIMEOUT { return ERR_TIMEOUT; }
    if n == NET_EARG { return ERR_URL; }
    return ERR_IO;
}


// --- Each connection's input ------------------------------------------------

// What has come on a connection and is not used yet is in c.buf while that
// connection is the one being read (c.buf_owner), else in c.store, as a
// record: u32 slot, u32 stream (0 here), u8 kind, u32 length, the bytes.
let K_IN: u8 = 1;

fn store_find(c: const Client&, slot: i64, stream: i64, kind: u8) -> i64, i64 {
    var p = 0;
    while p + 13 <= c.store.len {
        let n = rd_u(c.store, p + 9, 4) as! i64;
        if (rd_u(c.store, p, 4) as! i64) == slot && (rd_u(c.store, p + 4, 4) as! i64) == stream && c.store[p + 8] == kind {
            return p, n;
        }
        p += 13 + n;
    }
    return -1, 0;
}

fn store_put(c: Client&, slot: i64, stream: i64, kind: u8, data: const u8[:]) {
    if data.len == 0 { return; }
    let p, n = store_find(c, slot, stream, kind);
    if p < 0 {
        wr_u(c.store, slot as! u64, 4);
        wr_u(c.store, stream as! u64, 4);
        c.store.push(kind);
        wr_u(c.store, data.len as! u64, 4);
        c.store.append(data);
        return;
    }
    var rest: u8[>..] = [];
    rest.append(c.store[p + 13 + n..]);
    c.store.resize(p + 13 + n);
    c.store.append(data);
    c.store.append(rest);
    let total = n + data.len;
    for k in 4 { c.store[p + 9 + k] = ((total >> ((3 - k) * 8)) & 0xff) as! u8; }
}

// Appends the record's bytes to out, and drops the record.
fn store_take(c: Client&, slot: i64, stream: i64, kind: u8, out: u8[>..]&) {
    let p, n = store_find(c, slot, stream, kind);
    if p < 0 { return; }
    out.append(c.store[p + 13..p + 13 + n]);
    store_cut(c, p, 13 + n);
}

fn store_cut(c: Client&, p: i64, size: i64) {
    var rest: u8[>..] = [];
    rest.append(c.store[p + size..]);
    c.store.resize(p);
    c.store.append(rest);
}

// Drops every record of a slot.
fn store_drop(c: Client&, slot: i64) {
    var p = 0;
    while p + 13 <= c.store.len {
        let n = rd_u(c.store, p + 9, 4) as! i64;
        if (rd_u(c.store, p, 4) as! i64) == slot { store_cut(c, p, 13 + n); } else { p += 13 + n; }
    }
}

// Makes c.buf connection i's input.
fn use_buf(c: Client&, i: i64) {
    if c.buf_owner == i { return; }
    if c.buf_owner >= 0 { store_put(c, c.buf_owner, 0, K_IN, c.buf); }
    c.buf.clear();
    store_take(c, i, 0, K_IN, c.buf);
    c.buf_owner = i;
}

// What has come on connection i and is not used yet.
fn leftover(c: const Client&, i: i64) -> i64 {
    if c.buf_owner == i { return c.buf.len; }
    let p, n = store_find(c, i, 0, K_IN);
    return n;
}

// Sends the head held for another request (and what of its body there is).
fn flush_pend(c: Client&) {
    if c.pend.len == 0 || c.pend_owner < 0 { c.pend.clear(); return; }
    let i = c.pend_owner;
    if c.conns[i].used { conn_send(c, i, c.pend); }
    c.pend.clear();
}

// A gzip decoder for a response.
fn inflate_slot(c: Client&) -> i64 {
    for k in c.inflate_used.len {
        if !c.inflate_used[k] { c.inflate_used[k] = true; c.inflates[k] = gzip_decoder(); return k; }
    }
    c.inflates.push(gzip_decoder());
    c.inflate_used.push(true);
    return c.inflates.len - 1;
}

fn inflate_free(c: Client&, r: Response&) {
    if r.inflate >= 0 && r.inflate < c.inflate_used.len { c.inflate_used[r.inflate] = false; }
    r.inflate = -1;
}

// --- Connections -----------------------------------------------------------

fn conn_close(c: Client&, i: i64) {
    let pc: PoolConn& = c.conns[i];
    if !pc.used { return; }
    if pc.is_tls && tls::connected(pc.tc) {
        c.wire.clear();
        tls::close(pc.tc, c.wire);
        link_write_wire(c, i, 1000);
    }
    if pc.outer >= 0 {
        let o: OuterTls& = c.outer[pc.outer];
        if tls::connected(o.tc) {
            c.wire2.clear();
            tls::close(o.tc, c.wire2);
            httpnet_write(pc.fd, c.wire2, 1000);
            c.wire2.clear();
        }
        o.used = false;
        pc.outer = -1;
    }
    httpnet_close(pc.fd);
    pc.used = false;
    pc.idle = false;
    pc.fd = -1;
    store_drop(c, i);
    if c.buf_owner == i { c.buf.clear(); c.buf_owner = -1; }
    if c.pend_owner == i { c.pend.clear(); c.pend_owner = -1; }
}

// Closes every idle connection (Go's CloseIdleConnections).
fn close_idle(c: Client&) {
    for i in c.conns.len { if c.conns[i].used && c.conns[i].idle { conn_close(c, i); } }
}

fn new_slot(c: Client&) -> i64 {
    for i in c.conns.len { if !c.conns[i].used { return i; } }
    c.conns.push(PoolConn {
        used: false, gen: 0, idle: false, fd: -1, key: [], is_tls: false, reused: false, must_close: false, last_used: 0, server_name: [], sess_sig: 0,
        outer: -1, via_proxy: false, hc: client_conn(), tc: tls::client(c.tlscfg),
    });
    return c.conns.len - 1;
}

fn new_outer(c: Client&) -> i64 {
    for k in c.outer.len { if !c.outer[k].used { c.outer[k].used = true; return k; } }
    c.outer.push(OuterTls { used: true, server_name: [], sess_sig: 0, tc: tls::client(c.tlscfg) });
    return c.outer.len - 1;
}

// An idle connection for the key that the server has not closed, or -1.
fn take_idle(c: Client&, key: const u8[:]) -> i64 {
    var best = -1;
    for i in c.conns.len {
        let pc: PoolConn& = c.conns[i];
        if !pc.used || !pc.idle || pc.key[..] != key { continue; }
        // Something came while it was idle: its end, or bytes no request
        // asked for, and then it cannot carry a request; or, on TLS, only
        // handshake messages (a late NewSessionTicket, a KeyUpdate), read
        // here.
        if httpnet_readable(pc.fd) != 0 && !idle_drain(c, i) { conn_close(c, i); continue; }
        if best < 0 || pc.last_used > c.conns[best].last_used { best = i; }
    }
    if best >= 0 {
        c.conns[best].idle = false;
        c.conns[best].reused = true;
    }
    return best;
}

// Reads what came on idle connection i: true if it was TLS's own messages
// alone and the connection is still good.
fn idle_drain(c: Client&, i: i64) -> bool {
    if !c.conns[i].is_tls { return false; }
    var app: u8[>..] = [];
    var rounds = 0;
    while httpnet_readable(c.conns[i].fd) != 0 {
        rounds++;
        if rounds > 16 { return false; }
        c.mid.clear();
        let n = link_read(c, i, c.mid, 1000);
        if n <= 0 { c.mid.clear(); return false; }
        c.wire.clear();
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(c.conns[i].server_name[..]);
        let e = tls::client_feed(c.conns[i].tc, c.tlscfg, c.mid, c.wire, app);
        c.mid.clear();
        if c.wire.len > 0 { link_write_wire(c, i, 1000); }
        if e != 0 || app.len > 0 || tls::closed(c.conns[i].tc) { return false; }
        keep_session(c, i, false);
    }
    return true;
}

// Back to the pool, within the idle limits (the oldest idle ones go first),
// or closed.
fn conn_release(c: Client&, i: i64) {
    let pc: PoolConn& = c.conns[i];
    if !pc.used { return; }
    if !client_idle(pc.hc) || pc.must_close || leftover(c, i) > 0 || c.mid.len > 0 || c.opt.max_idle <= 0 || c.opt.max_idle_per_host <= 0 {
        conn_close(c, i);
        return;
    }
    pc.idle = true;
    pc.last_used = clock_ns();
    // The limits: per host, then in all.
    var rounds = 0;
    while rounds < c.conns.len + 1 {
        rounds++;
        var same = 0;
        var all = 0;
        var oldest_same = -1;
        var oldest = -1;
        for j in c.conns.len {
            let q: PoolConn& = c.conns[j];
            if !q.used || !q.idle { continue; }
            all++;
            if oldest < 0 || q.last_used < c.conns[oldest].last_used { oldest = j; }
            if q.key[..] == c.conns[i].key[..] {
                same++;
                if oldest_same < 0 || q.last_used < c.conns[oldest_same].last_used { oldest_same = j; }
            }
        }
        if same > c.opt.max_idle_per_host { conn_close(c, oldest_same); }
        else if all > c.opt.max_idle { conn_close(c, oldest); }
        else { break; }
    }
}

// --- TLS sessions ------------------------------------------------------------

// The cache of sessions to resume, as Go's LRU ClientSessionCache keyed by
// server name: at most opt.tls_sessions, the least recently used going
// first. Each record: the name's length (u8), the name, when it was last
// used (u64), the session's length (u32) and tls::session_bytes.

fn rd_u(b: const u8[:], pos: i64, n: i64) -> u64 {
    var v: u64 = 0;
    for k in n { v = (v << 8) | b[pos + k]; }
    return v;
}

fn wr_u(out: u8[>..]&, v: u64, n: i64) {
    for k in n { out.push(((v >> ((n - 1 - k) * 8) as! u64) & 0xff) as! u8); }
}

// Where the record for `name` starts, and its length; -1 if none.
fn session_find(c: const Client&, name: const u8[:]) -> i64, i64 {
    var pos = 0;
    while pos < c.sessions.len {
        let nl = c.sessions[pos] as i64;
        let sl = rd_u(c.sessions, pos + 1 + nl + 8, 4) as! i64;
        let size = 1 + nl + 8 + 4 + sl;
        if c.sessions[pos + 1..pos + 1 + nl] == name { return pos, size; }
        pos += size;
    }
    return -1, 0;
}

fn session_remove(c: Client&, pos: i64, size: i64) {
    var rest: u8[>..] = [];
    rest.append(c.sessions[pos + size..]);
    c.sessions.resize(pos);
    c.sessions.append(rest);
}

fn session_drop(c: Client&, name: const u8[:]) {
    let pos, size = session_find(c, name);
    if pos >= 0 { session_remove(c, pos, size); }
}

// The session kept for `name`, now the most recently used.
fn session_get(c: Client&, name: const u8[:]) -> tls::Session, bool {
    let pos, size = session_find(c, name);
    if pos < 0 { return tls::no_session(), false; }
    let nl = c.sessions[pos] as i64;
    let at = pos + 1 + nl + 8 + 4;
    let s, ok = tls::parse_session(c.sessions[at..pos + size]);
    if !ok { session_remove(c, pos, size); return tls::no_session(), false; }
    c.session_seq++;
    var stamp: u8[>..] = [];
    wr_u(stamp, c.session_seq as! u64, 8);
    for k in 8 { c.sessions[pos + 1 + nl + k] = stamp[k]; }
    return s, true;
}

fn session_put(c: Client&, name: const u8[:], s: const tls::Session&) {
    if c.opt.tls_sessions <= 0 || name.len == 0 || name.len > 255 { return; }
    session_drop(c, name);
    // Room for it: the least recently used go.
    while true {
        var count = 0;
        var oldest = -1;
        var oldest_size = 0;
        var oldest_seq: u64 = 0;
        var pos = 0;
        while pos < c.sessions.len {
            let nl = c.sessions[pos] as i64;
            let seq = rd_u(c.sessions, pos + 1 + nl, 8);
            let size = 1 + nl + 8 + 4 + (rd_u(c.sessions, pos + 1 + nl + 8, 4) as! i64);
            if oldest < 0 || seq < oldest_seq { oldest = pos; oldest_size = size; oldest_seq = seq; }
            count++;
            pos += size;
        }
        if count < c.opt.tls_sessions { break; }
        session_remove(c, oldest, oldest_size);
    }
    let b = tls::session_bytes(s);
    c.session_seq++;
    c.sessions.push(name.len as! u8);
    c.sessions.append(name);
    wr_u(c.sessions, c.session_seq as! u64, 8);
    wr_u(c.sessions, b.len as! u64, 4);
    c.sessions.append(b);
}

// What tells one ticket from the next: when it came, and its random age_add.
fn session_sig(s: const tls::Session&) -> u64 {
    return ((s.received_ms as! u64) << 32) ^ s.age_add ^ ((s.ticket.len as! u64) << 20) ^ 1;
}

// A new ticket on connection i (its own TLS, or an https proxy's beneath
// it when `outer`) goes to the cache.
fn keep_session(c: Client&, i: i64, outer: bool) {
    if c.opt.tls_sessions <= 0 { return; }
    let k = c.conns[i].outer;
    if outer && k < 0 { return; }
    var s = tls::no_session();
    var has = false;
    if outer { s, has = tls::session(c.outer[k].tc); } else { s, has = tls::session(c.conns[i].tc); }
    if !has { return; }
    let g = session_sig(s);
    var name: u8[>..] = [];
    if outer {
        if g == c.outer[k].sess_sig { return; }
        c.outer[k].sess_sig = g;
        name.append(c.outer[k].server_name[..]);
    } else {
        if g == c.conns[i].sess_sig { return; }
        c.conns[i].sess_sig = g;
        name.append(c.conns[i].server_name[..]);
    }
    session_put(c, name, s);
}

// The session to offer `name`, set in c.tlscfg (none if there is none).
fn offer_session(c: Client&, name: const u8[:]) -> bool {
    c.tlscfg.session = tls::no_session();
    if c.opt.tls_sessions <= 0 { return false; }
    let s, ok = session_get(c, name);
    if ok { c.tlscfg.session = s; }
    return ok;
}

// --- The link beneath a connection's own TLS ----------------------------------

// Sends c.wire: on the socket, or inside an https proxy's TLS.
fn link_write_wire(c: Client&, i: i64, timeout: i64) -> i64 {
    let pc: PoolConn& = c.conns[i];
    var n: i64 = 0;
    if pc.outer >= 0 {
        c.wire2.clear();
        if !tls::send(c.outer[pc.outer].tc, c.wire, c.wire2) { c.wire.clear(); return ERR_TLS; }
        n = httpnet_write(pc.fd, c.wire2, timeout as! i32);
        c.wire2.clear();
    } else {
        n = httpnet_write(pc.fd, c.wire, timeout as! i32);
    }
    c.wire.clear();
    return if n < 0 { net_error(n) } else { ERR_NONE };
}

// Reads from the socket: what came, unwrapped from an https proxy's TLS,
// is appended to `out`. 1 if bytes came, 0 at the end, or -ERR_*.
fn link_read(c: Client&, i: i64, out: u8[>..]&, timeout_op: i64) -> i64 {
    let pc: PoolConn& = c.conns[i];
    while true {
        let t = wait_ms(c, timeout_op);
        if t < 0 { return -ERR_TIMEOUT; }
        c.raw.resize(65536, 0);
        let n = httpnet_read(pc.fd, c.raw, t as! i32);
        if n < 0 { c.raw.clear(); return -net_error(n); }
        c.raw.resize(n);
        if n == 0 { return 0; }
        if pc.outer < 0 {
            out.append(c.raw);
            c.raw.clear();
            return 1;
        }
        let o: OuterTls& = c.outer[pc.outer];
        let before = out.len;
        c.wire2.clear();
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(o.server_name[..]);
        let e = tls::client_feed(o.tc, c.tlscfg, c.raw, c.wire2, out);
        c.raw.clear();
        if c.wire2.len > 0 { httpnet_write(pc.fd, c.wire2, 5000); c.wire2.clear(); }
        if e != 0 { return -ERR_TLS; }
        keep_session(c, i, true);
        if out.len > before { return 1; }
        if tls::closed(o.tc) { return 0; }
    }
    return 0;
}

// Writes all of `data` (application bytes) on the connection.
fn conn_send(c: Client&, i: i64, data: const u8[:]) -> i64 {
    let pc: PoolConn& = c.conns[i];
    c.wire.clear();
    if pc.is_tls {
        if !tls::send(pc.tc, data, c.wire) { return ERR_TLS; }
    } else {
        c.wire.append(data);
    }
    let t = wait_ms(c, c.opt.read_timeout_ms);
    if t < 0 { c.wire.clear(); return ERR_TIMEOUT; }
    return link_write_wire(c, i, t);
}

// Reads what comes into c.buf (decrypted): 1 if bytes came, 0 at the end
// of the stream (TLS's close_notify included), or -ERR_*.
fn conn_fill(c: Client&, i: i64) -> i64 { conn_fill_t(c, i, c.opt.read_timeout_ms) }

fn conn_fill_t(c: Client&, i: i64, timeout_op: i64) -> i64 {
    use_buf(c, i);
    let pc: PoolConn& = c.conns[i];
    if !pc.is_tls { return link_read(c, i, c.buf, timeout_op); }
    while true {
        let n = link_read(c, i, c.mid, timeout_op);
        if n <= 0 { return n; }
        let before = c.buf.len;
        c.wire.clear();
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(pc.server_name[..]);
        let e = tls::client_feed(pc.tc, c.tlscfg, c.mid, c.wire, c.buf);
        c.mid.clear();
        if c.wire.len > 0 { link_write_wire(c, i, 5000); }
        if e != 0 { return -ERR_TLS; }
        keep_session(c, i, false);
        if c.buf.len > before { return 1; }
        if tls::closed(pc.tc) { return 0; }
    }
    return 0;
}

fn tls_setup(c: Client&, name: const u8[:]) {
    c.tlscfg.server_name.clear();
    c.tlscfg.server_name.append(name);
    c.tlscfg.verify = !c.opt.insecure;
    if c.tlscfg.alpn.len == 0 { tls::add_alpn(c.tlscfg.alpn, "http/1.1"); }
}

// The connection's own TLS handshake for `name`, over its link.
fn conn_handshake(c: Client&, i: i64, name: const u8[:]) -> i64 {
    let pc: PoolConn& = c.conns[i];
    pc.is_tls = true;
    pc.server_name.clear();
    pc.server_name.append(name);
    tls_setup(c, name);
    pc.sess_sig = 0;
    let offered = offer_session(c, name);
    pc.tc = tls::client(c.tlscfg);
    c.wire.clear();
    tls::client_start(pc.tc, c.tlscfg, c.wire);
    let e = conn_handshake_run(c, i, name);
    c.tlscfg.session = tls::no_session();
    // A handshake that failed with a session offered drops it (as Go).
    if e != ERR_NONE && offered { session_drop(c, name); }
    if e == ERR_NONE { keep_session(c, i, false); }
    return e;
}

fn conn_handshake_run(c: Client&, i: i64, name: const u8[:]) -> i64 {
    use_buf(c, i);
    let pc: PoolConn& = c.conns[i];
    while !tls::connected(pc.tc) {
        let t = wait_ms(c, c.opt.connect_timeout_ms);
        if t < 0 { return ERR_TIMEOUT; }
        if c.wire.len > 0 {
            let we = link_write_wire(c, i, t);
            if we != ERR_NONE { return we; }
        }
        let n = link_read(c, i, c.mid, c.opt.connect_timeout_ms);
        if n <= 0 { c.mid.clear(); return if n == 0 { ERR_TLS } else { -n }; }
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(name);
        let e = tls::client_feed(pc.tc, c.tlscfg, c.mid, c.wire, c.buf);
        c.mid.clear();
        if e != 0 {
            if c.wire.len > 0 { link_write_wire(c, i, 1000); }
            return ERR_TLS;
        }
    }
    if c.wire.len > 0 {
        let t = wait_ms(c, c.opt.connect_timeout_ms);
        return link_write_wire(c, i, if t < 0 { 1 } else { t });
    }
    return ERR_NONE;
}

// TLS to an https proxy, on the socket, beneath what the connection sends.
fn outer_handshake(c: Client&, i: i64, name: const u8[:]) -> i64 {
    let k = new_outer(c);
    let o: OuterTls& = c.outer[k];
    o.server_name.clear();
    o.server_name.append(name);
    tls_setup(c, name);
    o.sess_sig = 0;
    c.conns[i].outer = k;
    let offered = offer_session(c, name);
    o.tc = tls::client(c.tlscfg);
    c.wire2.clear();
    tls::client_start(o.tc, c.tlscfg, c.wire2);
    let e = outer_handshake_run(c, i, k, name);
    c.tlscfg.session = tls::no_session();
    if e != ERR_NONE && offered { session_drop(c, name); }
    if e == ERR_NONE { keep_session(c, i, true); }
    return e;
}

fn outer_handshake_run(c: Client&, i: i64, k: i64, name: const u8[:]) -> i64 {
    let o: OuterTls& = c.outer[k];
    let fd = c.conns[i].fd;
    while !tls::connected(o.tc) {
        let t = wait_ms(c, c.opt.connect_timeout_ms);
        if t < 0 { return ERR_TIMEOUT; }
        if c.wire2.len > 0 {
            if httpnet_write(fd, c.wire2, t as! i32) < 0 { c.wire2.clear(); return ERR_IO; }
            c.wire2.clear();
        }
        c.raw.resize(65536, 0);
        let n = httpnet_read(fd, c.raw, t as! i32);
        if n <= 0 { c.raw.clear(); return if n == NET_ETIMEOUT { ERR_TIMEOUT } else if n == 0 { ERR_TLS } else { ERR_IO }; }
        c.raw.resize(n);
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(name);
        let e = tls::client_feed(o.tc, c.tlscfg, c.raw, c.wire2, c.mid);
        c.raw.clear();
        if e != 0 {
            if c.wire2.len > 0 { httpnet_write(fd, c.wire2, 1000); }
            c.wire2.clear();
            return ERR_TLS;
        }
    }
    if c.wire2.len > 0 {
        let t = wait_ms(c, c.opt.connect_timeout_ms);
        if httpnet_write(fd, c.wire2, if t < 0 { 1 } else { t as! i32 }) < 0 { c.wire2.clear(); return ERR_IO; }
        c.wire2.clear();
    }
    return ERR_NONE;
}

// A TCP connection to host:port in slot i.
fn conn_dial(c: Client&, i: i64, host: const u8[:], port: i64) -> i64 {
    var t = wait_ms(c, c.opt.connect_timeout_ms);
    if t < 0 { return ERR_TIMEOUT; }
    let fd = httpnet_connect(host, port as! i32, t as! i32);
    if fd < 0 { return net_error(fd); }
    let pc: PoolConn& = c.conns[i];
    pc.used = true;
    c.gen_seq++;
    pc.gen = c.gen_seq;
    pc.idle = false;
    pc.fd = fd;
    pc.is_tls = false;
    pc.reused = false;
    pc.must_close = false;
    pc.outer = -1;
    pc.via_proxy = false;
    pc.hc = client_conn();
    return ERR_NONE;
}

// --- Proxies ---------------------------------------------------------------

// Go's useProxy: whether NO_PROXY (and, for proxies from the environment,
// the rule that localhost and loopback addresses go direct) let `host`
// (ASCII, lowered, no brackets) on `port` go through the proxy.
fn use_proxy(c: const Client&, host: const u8[:], port: i64, loopback_rule: bool) -> bool {
    let ip, kind = parse_ip(host);
    if loopback_rule {
        if host == "localhost" { return false; }
        if kind != 0 && ip_is_loopback(ip, kind) { return false; }
    }
    var port_text: u8[>..] = [];
    format(port_text, port);
    var use = true;
    each_split(c.no_proxy, ',') {
        var low: u8[>..] = [];
        for ch in trim_ows(it) { low.push(lower(ch)); }
        // An entry outside ASCII in its ASCII form (Go's idnaASCII).
        var p, aok = to_ascii_host(low);
        if !aok { p.clear(); }
        if use && p.len > 0 {
            if p[..] == "*" { use = false; }
            // "host:port", "[v6]:port", or a host; a CIDR block "ip/bits".
            var phost = p[..];
            var pport: u8[>..] = [];
            let slash = position(p, '/');
            if slash > 0 {
                if kind != 0 && cidr_contains(p, ip, kind) { use = false; }
            } else {
                if phost.len > 0 && phost[0] == '[' {
                    let close = position(phost, ']');
                    if close > 0 {
                        if close + 1 < phost.len && phost[close + 1] == ':' { pport.append(phost[close + 2..]); }
                        phost = phost[1..close];
                    }
                } else {
                    let colon = last_index(phost, ':');
                    if colon > 0 && position(phost[..colon], ':') < 0 { pport.append(phost[colon + 1..]); phost = phost[..colon]; }
                }
                let pip, pkind = parse_ip(phost);
                if pkind != 0 {
                    if kind != 0 && ip_equal(ip, pip) && (pport.len == 0 || pport[..] == port_text[..]) { use = false; }
                } else if phost.len > 0 && kind == 0 {
                    // "*.example.com" and ".example.com" match subdomains;
                    // "example.com" matches it and its subdomains.
                    var dom = phost;
                    if starts_with(dom, "*.") { dom = dom[1..]; }
                    let match_host = dom[0] != '.';
                    var suffix: u8[>..] = [];
                    if match_host { suffix.push('.'); }
                    suffix.append(dom);
                    let hit = ends_with(host, suffix[..]) || (match_host && host == suffix[1..]);
                    if hit && (pport.len == 0 || pport[..] == port_text[..]) { use = false; }
                }
            }
        }
    };
    return use;
}

fn ip_equal(a: const u8[:], b: const u8[:]) -> bool { a == b }

// Whether "ip/bits" holds the address.
fn cidr_contains(p: const u8[:], ip: const u8[:], kind: i64) -> bool {
    let slash = position(p, '/');
    let net, nkind = parse_ip(p[..slash]);
    let bits, ok = parse_int(p[slash + 1..]);
    if nkind == 0 || !ok || bits < 0 { return false; }
    // An IPv4 block's bits count from the IPv4 part of the 16 bytes.
    let total = if nkind == 4 { bits + 96 } else { bits };
    if (nkind == 4 && bits > 32) || total > 128 { return false; }
    if (nkind == 4) != (kind == 4) { return false; }
    for b in 128 {
        if b >= total { break; }
        let m = (0x80 >> (b % 8)) as! u8;
        if (ip[b / 8] & m) != (net[b / 8] & m) { return false; }
    }
    return true;
}

// The proxy for a URL, as Go's Proxy funcs choose it: its URL text, or
// empty for none. Go's parseProxy: a value without a scheme is "http://"
// and the value.
fn proxy_for(c: const Client&, u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    if c.proxy_mode == PROXY_NONE { return out; }
    let sc = url_scheme(u);
    if sc != "http" && sc != "https" { return out; }
    let https = url_https(u);
    let p = if https { c.proxy_https[..] } else { c.proxy_http[..] };
    if p.len == 0 { return out; }
    if c.proxy_mode == PROXY_ENV {
        if !https && c.proxy_cgi { return out; }
        let h, ok = cookie_host(u);
        if !ok || !use_proxy(c, h, url_port(u), true) { return out; }
    } else if c.no_proxy.len > 0 {
        // One proxy for all, but for the hosts no_proxy names (curl's --noproxy).
        let h, ok = cookie_host(u);
        if !ok || !use_proxy(c, h, url_port(u), false) { return out; }
    }
    let pu, e = url_parse(p);
    if e != URL_OK || span_len(pu.scheme) == 0 || span_len(pu.host) == 0 { out.append("http://"); }
    out.append(p);
    return out;
}

// RFC 1928's CONNECT through a SOCKS5 proxy already connected in slot i,
// with RFC 1929's user name and password from the proxy URL if it has them.
fn socks5_connect(c: Client&, i: i64, pu: const Url&, host: const u8[:], port: i64) -> i64 {
    let user = url_username(pu);
    let pass = url_password(pu);
    let auth = pu.has_user;
    c.wire.clear();
    if auth { c.wire.append([5, 2, 0, 2]); } else { c.wire.append([5, 1, 0]); }
    var e = link_write_wire(c, i, wait_ms(c, c.opt.connect_timeout_ms));
    if e != ERR_NONE { return e; }
    var got: u8[>..] = [];
    e = read_at_least(c, i, got, 2);
    if e != ERR_NONE { return e; }
    if got[0] != 5 { return ERR_PROXY; }
    if got[1] == 2 && auth {
        if user.len > 255 || pass.len > 255 { return ERR_PROXY; }
        c.wire.push(1);
        c.wire.push(user.len as! u8);
        c.wire.append(user);
        c.wire.push(pass.len as! u8);
        c.wire.append(pass);
        e = link_write_wire(c, i, wait_ms(c, c.opt.connect_timeout_ms));
        if e != ERR_NONE { return e; }
        got.clear();
        e = read_at_least(c, i, got, 2);
        if e != ERR_NONE { return e; }
        if got[1] != 0 { return ERR_PROXY; }
    } else if got[1] != 0 {
        return ERR_PROXY;
    }
    got.clear();
    // The target by name (the proxy resolves it), or as an address.
    c.wire.append([5, 1, 0]);
    let ip, kind = parse_ip(host);
    if kind == 4 { c.wire.push(1); c.wire.append(ip[12..16]); }
    else if kind == 6 { c.wire.push(4); c.wire.append(ip[..]); }
    else {
        if host.len > 255 { return ERR_PROXY; }
        c.wire.push(3);
        c.wire.push(host.len as! u8);
        c.wire.append(host);
    }
    c.wire.push((port >> 8) as! u8);
    c.wire.push((port & 0xff) as! u8);
    e = link_write_wire(c, i, wait_ms(c, c.opt.connect_timeout_ms));
    if e != ERR_NONE { return e; }
    e = read_at_least(c, i, got, 5);
    if e != ERR_NONE { return e; }
    if got[0] != 5 || got[1] != 0 { return ERR_PROXY; }
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let alen: i64 = if got[3] == 1 { 4 } else if got[3] == 4 { 16 } else if got[3] == 3 { 1 + got[4] } else { -1 };
    if alen < 0 { return ERR_PROXY; }
    e = read_at_least(c, i, got, 4 + alen + 2);
    if e != ERR_NONE { return e; }
    if got.len != 4 + alen + 2 { return ERR_PROXY; }
    return ERR_NONE;
}

fn read_at_least(c: Client&, i: i64, got: u8[>..]&, n: i64) -> i64 {
    while got.len < n {
        let r = link_read(c, i, got, c.opt.connect_timeout_ms);
        if r == 0 { return ERR_PROXY; }
        if r < 0 { return -r; }
    }
    return ERR_NONE;
}

// A CONNECT tunnel to host:port through the HTTP proxy in slot i (RFC 9110
// §9.3.6). A refusal leaves its status and fields in c.proxy_status and
// c.proxy_fields (a 407's Proxy-Authenticate, say).
fn http_connect(c: Client&, i: i64, authority: const u8[:]) -> i64 {
    var req: u8[>..] = [];
    req.append("CONNECT ");
    req.append(authority);
    req.append(" HTTP/1.1\r\nHost: ");
    req.append(authority);
    req.append("\r\n");
    if c.proxy_authz.len > 0 { req.append("Proxy-Authorization: "); req.append(c.proxy_authz); req.append("\r\n"); }
    if c.opt.user_agent.len > 0 { req.append("User-Agent: "); req.append(c.opt.user_agent[..]); req.append("\r\n"); }
    req.append("\r\n");
    c.wire.clear();
    c.wire.append(req);
    var e = link_write_wire(c, i, wait_ms(c, c.opt.connect_timeout_ms));
    if e != ERR_NONE { return e; }
    var got: u8[>..] = [];
    let lim = default_limits();
    while true {
        let h, n = parse_response(got, lim);
        if n > 0 {
            if h.status >= 200 && h.status < 300 {
                // Nothing may come before the tunnel's first bytes are sent.
                if got.len > n { return ERR_PROXY; }
                return ERR_NONE;
            }
            if h.status < 200 { var rest: u8[>..] = []; rest.append(got[n..]); got.clear(); got.append(rest); continue; }
            c.proxy_status = h.status;
            c.proxy_fields.clear();
            for f in h.fields {
                c.proxy_fields.append(got[f.name.pos..f.name.end]);
                c.proxy_fields.append(": ");
                c.proxy_fields.append(got[f.value.pos..f.value.end]);
                c.proxy_fields.append("\r\n");
            }
            return ERR_PROXY;
        }
        if n < 0 { return ERR_PROXY; }
        let r = link_read(c, i, got, c.opt.connect_timeout_ms);
        if r == 0 { return ERR_PROXY; }
        if r < 0 { return -r; }
    }
    return ERR_PROXY;
}

// The pool's key for a URL reached directly: scheme, ASCII host, port.
fn origin_key(u: const Url&, out: u8[>..]&) -> bool {
    out.append(url_scheme(u));
    out.append("://");
    let h, ok = url_ascii_host(u);
    if !ok { return false; }
    out.append(h);
    out.push(':');
    format(out, url_port(u));
    return true;
}

// A connection for the URL: an idle one from the pool, else a new one,
// through the proxy proxy_for gives. The slot, or -ERR_*.
fn conn_for(c: Client&, u: const Url&, fresh: bool) -> i64 {
    let ptext = proxy_for(c, u);
    var pu = empty_url();
    var key: u8[>..] = [];
    var pscheme: u8[>..] = [];
    if ptext.len > 0 {
        let p, pe = url_parse(ptext);
        if pe != URL_OK { return -ERR_PROXY; }
        pu = copy(p);
        pscheme.append(url_scheme(pu));
        if pscheme[..] != "http" && pscheme[..] != "https" && pscheme[..] != "socks5" && pscheme[..] != "socks5h" {
            return -ERR_PROXY;
        }
        key.append(url_redacted(pu));
        key.push('|');
    }
    let direct_http = ptext.len > 0 && (pscheme[..] == "http" || pscheme[..] == "https") && !url_https(u);
    // Through an HTTP proxy, every http URL shares the proxy's connections
    // (Go's connectMethodKey without a target).
    if direct_http { key.append("http"); }
    else if !origin_key(u, key) { return -ERR_URL; }
    if key.len > 600 { return -ERR_URL; }
    if !fresh {
        let i = take_idle(c, key);
        if i >= 0 { return i; }
    }
    let host, ok = url_ascii_host(u);
    let port = url_port(u);
    if !ok || port < 0 { return -ERR_URL; }
    let i = new_slot(c);
    c.proxy_status = 0;
    if ptext.len == 0 {
        let e = conn_dial(c, i, host, port);
        if e != ERR_NONE { return -e; }
    } else {
        let phost, pok = url_ascii_host(pu);
        let pport = url_port(pu);
        if !pok || pport < 0 { return -ERR_PROXY; }
        let e = conn_dial(c, i, phost, pport);
        if e != ERR_NONE { return -(if e == ERR_TIMEOUT { e } else { ERR_PROXY }); }
        var pe = ERR_NONE;
        if pscheme[..] == "socks5" || pscheme[..] == "socks5h" {
            pe = socks5_connect(c, i, pu, host, port);
        } else {
            if pscheme[..] == "https" { pe = outer_handshake(c, i, phost); }
            if pe == ERR_NONE {
                if url_https(u) {
                    var auth: u8[>..] = [];
                    host_port_text(u, auth);
                    pe = http_connect(c, i, auth);
                } else {
                    c.conns[i].via_proxy = true;
                }
            }
        }
        if pe != ERR_NONE { conn_close(c, i); return -pe; }
    }
    c.conns[i].key.clear();
    c.conns[i].key.append(key);
    if url_https(u) {
        let he = conn_handshake(c, i, host);
        if he != ERR_NONE { conn_close(c, i); return -he; }
    }
    return i;
}

// "host:port" for CONNECT: the port always there (RFC 9112 §3.2.3).
fn host_port_text(u: const Url&, out: u8[>..]&) {
    let h, ok = url_ascii_host(u);
    if u.ipv6 { out.push('['); }
    out.append(h);
    if u.ipv6 { out.push(']'); }
    out.push(':');
    format(out, url_port(u));
}

// --- Requests --------------------------------------------------------------

// Go's isReplayable: a request it is safe to send again after the
// connection failed under it.
fn replayable(method: const u8[:], fields: const u8[:]) -> bool {
    if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE" { return true; }
    let a, ka = field_value(fields, "Idempotency-Key");
    let b, kb = field_value(fields, "X-Idempotency-Key");
    return ka || kb;
}

// Removes the field lines named `name`.
fn remove_field(fields: u8[>..]&, name: const u8[:]) {
    let kept = fields_without(fields, name);
    fields.clear();
    fields.append(kept);
}

// The field lines without those named `name`.
fn fields_without(fields: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        let colon = position(line, ':');
        if !(colon > 0 && eq_fold(line[..colon], name)) && line.len > 0 {
            out.append(line);
            out.append("\r\n");
        }
        pos = end + 2;
    }
    return out;
}

// Sends one request and reads its response's head: a Response whose body
// is to be read with read_body (or read_all), the connection checked out
// of the pool until it ends. `fields` from add_field, without
// Content-Length; a Host field in them is the Host sent (Go's
// Request.Host), else the URL's. `body` goes with a Content-Length, or in
// chunks if the fields have "Transfer-Encoding: chunked". Through an HTTP
// proxy the target is absolute-form and c.proxy_authz is sent as
// Proxy-Authorization. With "Expect: 100-continue" the body waits for the
// 100 (opt.expect_continue_ms), and is not sent if a final response comes
// first.
//
// A request on a reused connection that fails before any of the response
// came is sent again on a new one if it is replayable (Go's
// shouldRetryRequest).
fn round_trip(c: Client&, method: const u8[:], u: const Url&, fields: const u8[:], body: const u8[:]) -> Response {
    let te, has_te = field_value(fields, "Transfer-Encoding");
    if has_te && !eq_fold(te, "chunked") { return empty_response(ERR_REQUEST); }
    let f = fields_without(fields, "Transfer-Encoding");
    let length: i64 = if has_te { -1 } else { body.len };
    var attempt = 0;
    while true {
        attempt++;
        var r = begin_on(c, method, u, f, length, attempt > 1);
        if r.err == ERR_NONE {
            send_body(c, r, body, true, "");
            finish_request(c, r);
            if r.err == ERR_NONE { return r; }
        }
        // Nothing of a response came on a reused connection.
        if r.reused && attempt == 1 && r.status == -1 && r.err == ERR_IO && replayable(method, fields) { continue; }
        if r.status < 0 { r.status = 0; }
        return r;
    }
    return empty_response(ERR_IO);
}

// Starts a request whose body is sent as it comes: write_body, then
// end_request, which reads the response's head. `length` is the body's
// (Content-Length), or -1 to send it in chunks; fields as round_trip's,
// without Transfer-Encoding. The head goes with the first of the body.
// Such a request is not sent again on another connection once the body
// has begun, as Go does with a body it cannot get again.
fn begin_request(c: Client&, method: const u8[:], u: const Url&, fields: const u8[:], length: i64) -> Response {
    if has_field_named(fields, "Transfer-Encoding") || has_field_named(fields, "Content-Length") {
        return empty_response(ERR_REQUEST);
    }
    var attempt = 0;
    while true {
        attempt++;
        var r = begin_on(c, method, u, fields, length, attempt > 1);
        // The head could not be sent on a reused connection: nothing of the
        // request has gone, so it goes on a new one.
        if r.err == ERR_IO && r.reused && attempt == 1 && r.status == -1 { continue; }
        if r.status < 0 { r.status = 0; }
        return r;
    }
    return empty_response(ERR_IO);
}

fn has_field_named(fields: const u8[:], name: const u8[:]) -> bool {
    let v, ok = field_value(fields, name);
    return ok;
}

// Sends more of a begun request's body: ERR_NONE, or what failed. A final
// response that came already (a 413, say) stops the sending: the rest is
// dropped and end_request reads that response. After an error too,
// end_request reads a response if one came.
fn write_body(c: Client&, r: Response&, data: const u8[:]) -> i64 {
    if !r.sending { return ERR_STATE; }
    c.deadline = r.deadline;
    if r.length >= 0 && r.sent + data.len > r.length { return ERR_REQUEST; }
    send_body(c, r, data, false, "");
    return r.write_err;
}

// Ends a begun request's body (a chunked one with these trailer fields,
// "Name: value\r\n" lines) and reads the response's head into r, as
// round_trip's. A body shorter than its declared length is ERR_REQUEST
// (as Go's "ContentLength=N with Body length M"), and the connection is
// closed.
fn end_request(c: Client&, r: Response&, trailer: const u8[:]) -> i64 {
    if !r.sending { return ERR_STATE; }
    c.deadline = r.deadline;
    if r.length >= 0 && r.sent != r.length && !r.early && r.write_err == ERR_NONE {
        let i = r.conn;
        conn_close(c, i);
        let url_t = copy_url_text(r);
        reset_response(r, ERR_REQUEST);
        set_url(r, url_t);
        return ERR_REQUEST;
    }
    send_body(c, r, "", true, trailer);
    finish_request(c, r);
    if r.status < 0 { r.status = 0; }
    return r.err;
}

fn copy_url_text(r: const Response&) -> u8[>..] {
    var t: u8[>..] = [];
    t.append(response_url(r));
    return t;
}

fn set_url(r: Response&, t: const u8[:]) {
    r.data.clear();
    r.data.append(t);
    r.url = span(0, r.data.len);
}

// The connection and the head (held in c.pend until the body's first
// bytes go, unless the request expects a 100). An error with status -1:
// nothing was sent on a reused connection.
fn begin_on(c: Client&, method: const u8[:], u: const Url&, fields: const u8[:], length: i64, fresh: bool) -> Response {
    var r = empty_response(ERR_NONE);
    set_url(r, url_text(u));
    r.deadline = c.deadline;
    if url_check_http(u) != URL_OK { r.err = ERR_URL; return r; }
    var host: u8[>..] = [];
    let given, has_host = field_value(fields, "Host");
    if has_host { host.append(given); } else if !host_port_field(u, host) { r.err = ERR_URL; return r; }
    let i = conn_for(c, u, fresh);
    if i < 0 { r.err = -i; return r; }
    r.reused = c.conns[i].reused;
    r.gen = c.conns[i].gen;
    use_buf(c, i);
    c.buf.clear();
    c.mid.clear();
    if c.pend_owner != i { flush_pend(c); }
    c.pend.clear();
    c.pend_owner = i;
    var target: u8[>..] = [];
    var f = fields_without(fields, "Host");
    if c.conns[i].via_proxy {
        absolute_target(u, target);
        if c.proxy_authz.len > 0 { add_field(f, "Proxy-Authorization", c.proxy_authz); }
    } else {
        request_target(u, target);
    }
    // No body and a method that has none: no Content-Length (Go's
    // outgoingLength); POST, PUT and PATCH say 0.
    if !client_request(c.conns[i].hc, method, target, host, f, length, c.pend) {
        c.pend.clear();
        conn_release(c, i);
        r.err = ERR_REQUEST;
        return r;
    }
    r.conn = i;
    r.sending = true;
    r.body_done = false;
    r.length = length;
    let ex, has_ex = field_value(fields, "Expect");
    if has_ex && eq_fold(ex, "100-continue") && length != 0 {
        let se = conn_send(c, i, c.pend);
        c.pend.clear();
        if se != ERR_NONE {
            conn_close(c, i);
            r.conn = -1;
            r.sending = false;
            r.err = se;
            r.status = -1;
            return r;
        }
        if c.opt.expect_continue_ms > 0 { wait_continue(c, r); }
    }
    return r;
}

// Sends c.pend (the head, if it has not gone) and `data`, as a chunk if the
// body is chunked, and with `last` the end: the last chunk and trailer.
fn send_body(c: Client&, r: Response&, data: const u8[:], last: bool, trailer: const u8[:]) {
    let i = r.conn;
    if c.pend_owner != i { flush_pend(c); c.pend_owner = i; }
    if r.early || r.write_err != ERR_NONE { c.pend.clear(); return; }
    // A response that has come already ends the sending.
    if data.len > 0 && r.sent > 0 { poll_early(c, r); }
    if r.early || r.write_err != ERR_NONE { c.pend.clear(); return; }
    if r.length < 0 {
        if data.len > 0 { write_chunk(c.pend, data); }
        if last { write_last_chunk(c.pend, trailer); }
    } else {
        c.pend.append(data);
    }
    r.sent += data.len;
    if c.pend.len == 0 { return; }
    let se = conn_send(c, i, c.pend);
    c.pend.clear();
    if se != ERR_NONE { r.write_err = se; }
}

// Whether a final response has come while the body is being sent: what
// came is read without waiting; a 100 (or other 1xx) is taken, a final
// head is left for read_head.
fn poll_early(c: Client&, r: Response&) {
    let i = r.conn;
    let n = conn_poll(c, i);
    if n <= 0 { r.early = true; return; }
    peek_head(c, r);
}

// Takes interim responses from the front of c.buf; a final one there (or
// one that does not parse) makes the request early.
fn peek_head(c: Client&, r: Response&) -> bool {
    use_buf(c, r.conn);
    let lim = default_limits();
    while c.buf.len > 0 {
        let h, n = parse_response(c.buf, lim);
        if n == NEED_MORE { return false; }
        if n < 0 { r.early = true; return true; }
        if h.status >= 100 && h.status < 200 && h.status != 101 {
            let cont = h.status == 100;
            drop_front(c.buf, n);
            if cont { return true; }
            continue;
        }
        r.early = true;
        return true;
    }
    return false;
}

// Expect: 100-continue: waits up to opt.expect_continue_ms for the 100,
// or a final response (then the body is not sent).
fn wait_continue(c: Client&, r: Response&) {
    let i = r.conn;
    let end = clock_ns() + c.opt.expect_continue_ms * 1000000;
    while true {
        if peek_head(c, r) { return; }
        let left = (end - clock_ns()) / 1000000;
        if left <= 0 { return; }
        let n = conn_fill_t(c, i, left);
        if n == -ERR_TIMEOUT { return; }
        if n <= 0 { r.early = true; return; }
    }
}

// Reads what has come on connection i into c.buf without waiting: 1, 0 if
// the connection ended, or -ERR_*.
fn conn_poll(c: Client&, i: i64) -> i64 {
    use_buf(c, i);
    while httpnet_readable(c.conns[i].fd) != 0 {
        if !c.conns[i].is_tls {
            let n = link_read(c, i, c.buf, 1000);
            if n <= 0 { return n; }
            continue;
        }
        c.mid.clear();
        let n = link_read(c, i, c.mid, 1000);
        if n <= 0 { c.mid.clear(); return n; }
        c.wire.clear();
        c.tlscfg.server_name.clear();
        c.tlscfg.server_name.append(c.conns[i].server_name[..]);
        let e = tls::client_feed(c.conns[i].tc, c.tlscfg, c.mid, c.wire, c.buf);
        c.mid.clear();
        if c.wire.len > 0 { link_write_wire(c, i, 1000); }
        if e != 0 { return -ERR_TLS; }
        keep_session(c, i, false);
        if tls::closed(c.conns[i].tc) { return 0; }
    }
    return 1;
}

// The head of the response to a request whose body has gone (or was cut
// short): into r. A body not all sent closes the connection after the
// response.
fn finish_request(c: Client&, r: Response&) {
    let i = r.conn;
    r.sending = false;
    if i < 0 { return; }
    let incomplete = r.early || r.write_err != ERR_NONE;
    if incomplete { c.conns[i].must_close = true; }
    let werr = r.write_err;
    let reused = r.reused;
    let deadline = r.deadline;
    let gen = r.gen;
    read_head(c, i, r);
    r.reused = reused;
    r.deadline = deadline;
    r.gen = gen;
    if r.err != ERR_NONE {
        conn_close(c, i);
        r.conn = -1;
        // No response to show for a body that could not be sent: that error.
        if werr != ERR_NONE { r.err = werr; }
    }
}

// The response head (1xx ones skipped). On an error, status -1 says
// nothing at all came (the request may be retried).
fn read_head(c: Client&, i: i64, r: Response&) {
    use_buf(c, i);
    let url_t = copy_url_text(r);
    reset_response(r, ERR_NONE);
    set_url(r, url_t);
    var got_any = false;
    var eof = false;
    var trailer: u8[>..] = [];
    var body: u8[>..] = [];
    while true {
        let pc: PoolConn& = c.conns[i];
        let ev, h = client_read(pc.hc, c.buf, body, trailer);
        if ev.kind == EV_RESPONSE {
            got_any = true;
            if h.status >= 100 && h.status < 200 && h.status != 101 {
                drop_front(c.buf, ev.used);
                continue;
            }
            r.status = h.status;
            r.minor = h.minor;
            let rp = r.data.len;
            r.data.append(c.buf[h.reason.pos..h.reason.end]);
            r.reason = span(rp, r.data.len);
            let fp = r.data.len;
            for f in h.fields {
                r.data.append(c.buf[f.name.pos..f.name.end]);
                r.data.append(": ");
                r.data.append(c.buf[f.value.pos..f.value.end]);
                r.data.append("\r\n");
            }
            r.fields = span(fp, r.data.len);
            r.body = span(r.data.len, r.data.len);
            r.trailer = r.body;
            drop_front(c.buf, ev.used);
            r.conn = i;
            r.reused = pc.reused;
            if pc.is_tls { r.tls_version = tls::version(pc.tc); r.tls_resumed = tls::resumed(pc.tc); }
            r.body_done = client_idle(pc.hc) || client_closed(pc.hc);
            if h.status == 101 { r.err = ERR_PROTOCOL; r.status = 0; conn_close(c, i); r.conn = -1; return; }
            if r.body_done { finish_body(c, r); }
            return;
        }
        if ev.kind == EV_ERROR { r.err = ERR_PROTOCOL; return; }
        if ev.kind != EV_NEED_MORE { r.err = ERR_PROTOCOL; return; }
        if eof {
            r.err = ERR_IO;
            if !got_any && c.buf.len == 0 { r.status = -1; }
            return;
        }
        let n = conn_fill(c, i);
        if n < 0 {
            r.err = -n;
            if !got_any && c.buf.len == 0 && -n == ERR_IO { r.status = -1; }
            return;
        }
        if n == 0 { eof = true; }
    }
    return;
}

fn drop_front(b: u8[>..]&, n: i64) {
    if n <= 0 { return; }
    if n >= b.len { b.clear(); return; }
    let rest = b.len - n;
    for k in rest { b[k] = b[n + k]; }
    b.resize(rest);
}

// The body is all read: the connection goes back to the pool or closes.
fn finish_body(c: Client&, r: Response&) {
    if r.conn >= 0 {
        let i = r.conn;
        r.conn = -1;
        if client_closed(c.conns[i].hc) { conn_close(c, i); } else { conn_release(c, i); }
    }
    r.body_done = true;
}

// Reads more of the body as it came on the wire (gzip or not).
fn read_wire_body(c: Client&, r: Response&, out: u8[>..]&) -> i64 {
    if r.body_done || r.conn < 0 { return 0; }
    let i = r.conn;
    // Its connection is gone (closed under it, the slot used again).
    if !c.conns[i].used || c.conns[i].gen != r.gen { r.conn = -1; r.body_done = true; return -ERR_IO; }
    c.deadline = r.deadline;
    var trailer: u8[>..] = [];
    var eof = false;
    while true {
        let before = out.len;
        use_buf(c, i);
        let ev, h = client_read(c.conns[i].hc, c.buf, out, trailer);
        drop_front(c.buf, ev.used);
        if ev.kind == EV_END {
            if trailer.len > 0 {
                let tp = r.data.len;
                append_trailer(r.data, trailer);
                r.trailer = span(tp, r.data.len);
            }
            finish_body(c, r);
            return out.len - before;
        }
        // A chunk-size line alone appends nothing: read on, so 0 means the end.
        if ev.kind == EV_BODY {
            if out.len > before { return out.len - before; }
            continue;
        }
        if ev.kind != EV_NEED_MORE { conn_close(c, i); r.conn = -1; r.body_done = true; return -ERR_PROTOCOL; }
        if eof {
            let e = client_eof(c.conns[i].hc);
            conn_close(c, i);
            r.conn = -1;
            r.body_done = true;
            return if e.kind == EV_END { 0 } else { -ERR_IO };
        }
        let n = conn_fill(c, i);
        if n < 0 { conn_close(c, i); r.conn = -1; r.body_done = true; return n; }
        if n == 0 { eof = true; }
    }
    return 0;
}

// Reads more of the body, decoded if it is gzip that the client asked
// for, appending it to `out`: how many bytes (0 at the end, when the
// connection has gone back to the pool), or -ERR_* (the connection is
// closed then). The trailer, after a chunked body, goes to the response's
// data.
fn read_body(c: Client&, r: Response&, out: u8[>..]&) -> i64 {
    if !r.decode || r.inflate < 0 { return read_wire_body(c, r, out); }
    var wire: u8[>..] = [];
    let k = r.inflate;
    while true {
        if r.body_done {
            let whole = inflate_done(c.inflates[k]);
            inflate_free(c, r);
            if !whole { return -ERR_DECODE; }
            return 0;
        }
        wire.clear();
        let n = read_wire_body(c, r, wire);
        if n < 0 { inflate_free(c, r); return n; }
        let before = out.len;
        if inflate_feed(c.inflates[k], wire, out) != 0 {
            if r.conn >= 0 { conn_close(c, r.conn); r.conn = -1; }
            r.body_done = true;
            inflate_free(c, r);
            return -ERR_DECODE;
        }
        // The body ended: the gzip stream must have ended whole with it.
        if r.body_done {
            let whole = inflate_done(c.inflates[k]);
            inflate_free(c, r);
            if !whole { return -ERR_DECODE; }
        }
        if out.len > before { return out.len - before; }
        if r.body_done { return 0; }
    }
    return 0;
}

// The trailer as chunked_feed leaves it ("Name: value" lines with CRLF), as
// field lines.
fn append_trailer(data: u8[>..]&, trailer: const u8[:]) {
    var pos = 0;
    while pos < trailer.len {
        var end = find(trailer[pos..], "\r\n");
        end = if end < 0 { trailer.len } else { pos + end };
        let line = trailer[pos..end];
        let colon = position(line, ':');
        if colon > 0 {
            data.append(line[..colon]);
            data.append(": ");
            data.append(trim_ows(line[colon + 1..]));
            data.append("\r\n");
        }
        pos = end + 2;
    }
}

// Stops reading the body: the connection closes, unless the rest of a
// small body is already here or comes at once (Go reads up to 2 KB of it
// to keep the connection).
fn close_body(c: Client&, r: Response&) {
    inflate_free(c, r);
    if r.body_done || r.conn < 0 { r.body_done = true; return; }
    if !c.conns[r.conn].used || c.conns[r.conn].gen != r.gen { r.conn = -1; r.body_done = true; return; }
    var sink: u8[>..] = [];
    var rounds = 0;
    while !r.body_done && sink.len <= 2048 && rounds < 4 {
        rounds++;
        let n = read_wire_body(c, r, sink);
        if n < 0 { return; }
    }
    if !r.body_done {
        conn_close(c, r.conn);
        r.conn = -1;
        r.body_done = true;
    }
}

// Reads the rest of the body into the response (r.body), up to the
// client's max_body.
fn read_all(c: Client&, r: Response&) -> i64 {
    var body: u8[>..] = [];
    while !r.body_done {
        let n = read_body(c, r, body);
        if n < 0 { r.err = -n; return -n; }
        if body.len > c.opt.max_body { close_body(c, r); r.err = ERR_TOO_LARGE; return ERR_TOO_LARGE; }
    }
    // (read_body found any gzip stream that did not end whole.)
    // The body goes before the trailer, which read_body put at the end.
    var t: u8[>..] = [];
    let had_trailer = span_len(r.trailer) > 0;
    if had_trailer {
        t.append(response_trailer(r));
        r.data.resize(r.trailer.pos);
    }
    let bp = r.data.len;
    r.data.append(body);
    r.body = span(bp, r.data.len);
    let tp = r.data.len;
    r.data.append(t);
    r.trailer = span(tp, r.data.len);
    return ERR_NONE;
}

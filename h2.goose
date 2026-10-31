// http.h2: HTTP/2 (RFC 9113) connections without I/O, server and client:
// frames, settings, streams and their states, flow control, and header
// blocks through HPACK, with HTTP/2's rules for messages (§8). The caller
// keeps the bytes that have arrived in a buffer of its own and asks the
// connection what they hold, one event at a time, as with http.conn1:
//
//   var c = http::h2_conn(http::h2_server_options());
//   http::h2_start(c, out);                      // our SETTINGS
//   loop {
//       let ev = http::h2_read(c, buf, fields, body, out);
//       // EV2_HEADERS: a request (or response, or trailers) on ev.stream,
//       //   its fields as "name: value\r\n" lines in `fields`, the
//       //   pseudo-header fields first (h2_field reads them)
//       // EV2_DATA: body bytes appended to `body` (h2_consumed when used)
//       // EV2_RESET, EV2_GOAWAY, EV2_WINDOW (more may be sent), EV2_NONE
//       // EV2_NEED_MORE: read more into buf; EV2_ERROR: send out, close
//       // then drop ev.used bytes from buf; send `out`
//   }
//   http::h2_respond(c, stream, 200, fields, false, out);
//   let n = http::h2_data(c, stream, data, true, out);   // as much as the windows allow
//
// Everything a connection keeps is of fixed size (some 27 KB): up to
// H2_MAX_STREAMS streams at once, and HPACK tables of 4096 bytes. A header
// block is read only once all of it (HEADERS and its CONTINUATIONs) is in
// the caller's buffer, up to the header list limit.

namespace http;

import std;
import http;
import h1;
import hpack;

let H2_PREFACE: const u8[:] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
let H2_MAX_STREAMS: i64 = 256;

// Frame types (§6) and flags.
let F2_DATA: u8 = 0;
let F2_HEADERS: u8 = 1;
let F2_PRIORITY: u8 = 2;
let F2_RST_STREAM: u8 = 3;
let F2_SETTINGS: u8 = 4;
let F2_PUSH_PROMISE: u8 = 5;
let F2_PING: u8 = 6;
let F2_GOAWAY: u8 = 7;
let F2_WINDOW_UPDATE: u8 = 8;
let F2_CONTINUATION: u8 = 9;

let FL2_END_STREAM: u8 = 0x1;
let FL2_ACK: u8 = 0x1;
let FL2_END_HEADERS: u8 = 0x4;
let FL2_PADDED: u8 = 0x8;
let FL2_PRIORITY: u8 = 0x20;

// Error codes (§7).
let E2_NO_ERROR: i64 = 0;
let E2_PROTOCOL: i64 = 1;
let E2_INTERNAL: i64 = 2;
let E2_FLOW_CONTROL: i64 = 3;
let E2_SETTINGS_TIMEOUT: i64 = 4;
let E2_STREAM_CLOSED: i64 = 5;
let E2_FRAME_SIZE: i64 = 6;
let E2_REFUSED_STREAM: i64 = 7;
let E2_CANCEL: i64 = 8;
let E2_COMPRESSION: i64 = 9;
let E2_CONNECT: i64 = 10;
let E2_ENHANCE_YOUR_CALM: i64 = 11;
let E2_INADEQUATE_SECURITY: i64 = 12;
let E2_HTTP_1_1_REQUIRED: i64 = 13;

// Settings (§6.5.2).
let S2_HEADER_TABLE_SIZE: i64 = 1;
let S2_ENABLE_PUSH: i64 = 2;
let S2_MAX_CONCURRENT_STREAMS: i64 = 3;
let S2_INITIAL_WINDOW_SIZE: i64 = 4;
let S2_MAX_FRAME_SIZE: i64 = 5;
let S2_MAX_HEADER_LIST_SIZE: i64 = 6;

let H2_MAX_WINDOW: i64 = 0x7fffffff;

// Events.
let EV2_NEED_MORE: u8 = 0;
let EV2_NONE: u8 = 1;           // a frame the connection took care of
let EV2_HEADERS: u8 = 2;        // a header blk: request, response (1xx too), or trailers
let EV2_DATA: u8 = 3;           // body bytes (perhaps none, with end_stream)
let EV2_RESET: u8 = 4;          // the stream is gone: the peer's RST_STREAM, or ours (local) for a malformed message
let EV2_GOAWAY: u8 = 5;         // the peer will take no stream above last_stream
let EV2_WINDOW: u8 = 6;         // more may be sent: on `stream`, or on every stream (0)
let EV2_ERROR: u8 = 7;          // the connection failed; out holds our GOAWAY
let EV2_PING: u8 = 8;           // the answer to our PING

struct H2Event {
    kind: u8,
    used: i64,                  // bytes of the buffer this event took
    stream: i64,
    end_stream: bool,           // HEADERS, DATA: the peer's side of the stream ended
    trailers: bool,             // HEADERS: a trailer section
    interim: bool,              // HEADERS: a 1xx response
    status: i64,                // HEADERS (client): the :status
    code: i64,                  // RESET, GOAWAY, ERROR: the error code
    local: bool,                // RESET: we reset it (a malformed message)
    last_stream: i64,           // GOAWAY
}

fn h2_event(kind: u8, used: i64) -> H2Event {
    H2Event { kind: kind, used: used, stream: 0, end_stream: false, trailers: false, interim: false, status: 0,
              code: 0, local: false, last_stream: 0 }
}

// One side's settings.
struct H2Settings {
    header_table_size: i64,
    enable_push: bool,
    max_concurrent_streams: i64,
    initial_window_size: i64,
    max_frame_size: i64,
    max_header_list_size: i64,
}

fn h2_default_settings() -> H2Settings {
    H2Settings { header_table_size: 4096, enable_push: true, max_concurrent_streams: 1 << 31, initial_window_size: 65535,
                 max_frame_size: 16384, max_header_list_size: 1 << 40 }
}

// What a connection advertises and allows.
struct H2Options {
    server: bool,
    max_concurrent_streams: i64,    // streams the peer may open (a server's; Go's 250)
    stream_window: i64,             // each stream's receive window (Go: 1 MiB a server, 4 MiB a client)
    conn_window: i64,               // the connection's (Go: 1 MiB a server)
    max_frame_size: i64,            // the largest frame we take (16384, the least)
    max_header_list: i64,           // the largest header list we take (§4.1 of RFC 7541's measure; past it a server answers 431)
    header_table_size: i64,         // our decoder's table (at most HPACK_MAX)
}

fn h2_server_options() -> H2Options {
    H2Options { server: true, max_concurrent_streams: 250, stream_window: 1 << 20, conn_window: 1 << 20,
                max_frame_size: 16384, max_header_list: 65536, header_table_size: 4096 }
}

fn h2_client_options() -> H2Options {
    H2Options { server: false, max_concurrent_streams: 100, stream_window: 4 << 20, conn_window: 16 << 20,
                max_frame_size: 16384, max_header_list: 65536, header_table_size: 4096 }
}

// Stream states (§5.1); a free slot is ST2_IDLE.
let ST2_IDLE: u8 = 0;
let ST2_OPEN: u8 = 1;
let ST2_HALF_LOCAL: u8 = 2;     // we have ended our side
let ST2_HALF_REMOTE: u8 = 3;    // the peer has ended its side

struct H2Stream {
    id: i64,
    state: u8,
    send_window: i64,
    recv_window: i64,           // what the peer may still send
    unacked: i64,               // received and consumed, not yet given back by WINDOW_UPDATE
    clen: i64,                  // the peer's content-length, or -1
    received: i64,              // DATA bytes from the peer
    got_head: bool,             // the peer's (final) header section came
    head_request: bool,         // a client's stream for HEAD: the response has no content
    no_content: bool,           // a response that has none (204, 304)
}

fn h2_free_stream() -> H2Stream {
    H2Stream { id: 0, state: ST2_IDLE, send_window: 0, recv_window: 0, unacked: 0, clen: -1, received: 0,
               got_head: false, head_request: false, no_content: false }
}

let C2_PREFACE: u8 = 0;         // a server's: the client's preface has not come yet
let C2_SETTINGS: u8 = 1;        // the peer's first SETTINGS has not come yet
let C2_OPEN: u8 = 2;
let C2_CLOSED: u8 = 3;

struct H2Conn {
    opt: H2Options,
    state: u8,
    peer: H2Settings,
    settings_unacked: i64,      // our SETTINGS the peer has not acknowledged
    conn_send: i64,
    conn_recv: i64,
    conn_unacked: i64,
    next_id: i64,               // a client's next stream
    last_peer: i64,             // the highest stream the peer opened
    goaway_sent: bool,
    goaway_got: bool,
    peer_last: i64,             // the peer's GOAWAY's last stream
    active: i64,
    reset_ring: i64[32],        // streams we reset lately: frames still in flight on them are dropped
    reset_at: i64,
    streams: H2Stream[256],
    enc: HpackTable,
    dec: HpackTable,
}

fn h2_conn(opt: H2Options) -> H2Conn {
    var c = H2Conn {
        opt: opt, state: if opt.server { C2_PREFACE } else { C2_SETTINGS }, peer: h2_default_settings(),
        settings_unacked: 0, conn_send: 65535, conn_recv: 65535, conn_unacked: 0,
        next_id: if opt.server { 2 } else { 1 }, last_peer: 0,
        goaway_sent: false, goaway_got: false, peer_last: 0, active: 0, reset_ring: [0; 32], reset_at: 0,
        streams: [h2_free_stream(); 256], enc: hpack_table(4096), dec: hpack_table(opt.header_table_size),
    };
    return c;
}

fn h2_closed(c: const H2Conn&) -> bool { c.state == C2_CLOSED }

// --- Frames ------------------------------------------------------------------

fn put_u32(out: u8[>..]&, v: i64) {
    out.push(((v >> 24) & 0xff) as! u8);
    out.push(((v >> 16) & 0xff) as! u8);
    out.push(((v >> 8) & 0xff) as! u8);
    out.push((v & 0xff) as! u8);
}

fn get_u32(b: const u8[:], at: i64) -> i64 {
    return ((b[at] as i64) << 24) | ((b[at + 1] as i64) << 16) | ((b[at + 2] as i64) << 8) | (b[at + 3] as i64);
}

fn frame_head(out: u8[>..]&, len: i64, ty: u8, flags: u8, stream: i64) {
    out.push(((len >> 16) & 0xff) as! u8);
    out.push(((len >> 8) & 0xff) as! u8);
    out.push((len & 0xff) as! u8);
    out.push(ty);
    out.push(flags);
    put_u32(out, stream & 0x7fffffff);
}

fn h2_settings_frame(c: H2Conn&, out: u8[>..]&) {
    var p: u8[>..] = [];
    fn setting(id: i64, v: i64) { p.push(0); p.push(id as! u8); put_u32(p, v); }
    setting(S2_HEADER_TABLE_SIZE, c.opt.header_table_size);
    if !c.opt.server { setting(S2_ENABLE_PUSH, 0); }
    if c.opt.server { setting(S2_MAX_CONCURRENT_STREAMS, c.opt.max_concurrent_streams); }
    setting(S2_INITIAL_WINDOW_SIZE, c.opt.stream_window);
    setting(S2_MAX_FRAME_SIZE, c.opt.max_frame_size);
    setting(S2_MAX_HEADER_LIST_SIZE, c.opt.max_header_list);
    frame_head(out, p.len, F2_SETTINGS, 0, 0);
    out.append(p);
    c.settings_unacked++;
}

// The start of the connection: a client's preface, then our SETTINGS, and
// a WINDOW_UPDATE that opens the connection's window to opt.conn_window.
fn h2_start(c: H2Conn&, out: u8[>..]&) {
    if !c.opt.server { out.append(H2_PREFACE); }
    h2_settings_frame(c, out);
    if c.opt.conn_window > 65535 {
        frame_head(out, 4, F2_WINDOW_UPDATE, 0, 0);
        put_u32(out, c.opt.conn_window - 65535);
        c.conn_recv = c.opt.conn_window;
    }
}

fn h2_rst(out: u8[>..]&, stream: i64, code: i64) {
    frame_head(out, 4, F2_RST_STREAM, 0, stream);
    put_u32(out, code);
}

// A connection error (§5.4.1): our GOAWAY, and the connection is done.
fn h2_fail(c: H2Conn&, code: i64, out: u8[>..]&) -> H2Event {
    if c.state != C2_CLOSED {
        frame_head(out, 8, F2_GOAWAY, 0, 0);
        put_u32(out, c.last_peer);
        put_u32(out, code);
        c.goaway_sent = true;
    }
    c.state = C2_CLOSED;
    var ev = h2_event(EV2_ERROR, 0);
    ev.code = code;
    return ev;
}

// A graceful GOAWAY (NO_ERROR): streams open now go on, no new ones are taken.
fn h2_goaway(c: H2Conn&, out: u8[>..]&) {
    if c.goaway_sent || c.state == C2_CLOSED { return; }
    frame_head(out, 8, F2_GOAWAY, 0, 0);
    put_u32(out, c.last_peer);
    put_u32(out, E2_NO_ERROR);
    c.goaway_sent = true;
}

fn h2_ping(out: u8[>..]&, data: const u8[:]) {
    frame_head(out, 8, F2_PING, 0, 0);
    for k in 8 { out.push(if k < data.len { data[k] } else { 0 }); }
}

// --- Streams -----------------------------------------------------------------

fn h2_find(c: const H2Conn&, id: i64) -> i64 {
    if id == 0 { return -1; }
    for k in H2_MAX_STREAMS { if c.streams[k].id == id { return k; } }
    return -1;
}

fn h2_new_stream(c: H2Conn&, id: i64) -> i64 {
    for k in H2_MAX_STREAMS {
        if c.streams[k].id == 0 {
            c.streams[k] = h2_free_stream();
            c.streams[k].id = id;
            c.streams[k].state = ST2_OPEN;
            c.streams[k].send_window = c.peer.initial_window_size;
            c.streams[k].recv_window = c.opt.stream_window;
            c.active++;
            return k;
        }
    }
    return -1;
}

fn h2_free(c: H2Conn&, k: i64) {
    if c.streams[k].id == 0 { return; }
    c.streams[k] = h2_free_stream();
    c.active--;
}

fn h2_remember_reset(c: H2Conn&, id: i64) {
    c.reset_ring[c.reset_at] = id;
    c.reset_at = (c.reset_at + 1) % 32;
}

fn h2_was_reset(c: const H2Conn&, id: i64) -> bool {
    for k in 32 { if c.reset_ring[k] == id { return true; } }
    return false;
}

// Resets stream id (ours to say): RST_STREAM, and it is gone.
fn h2_reset(c: H2Conn&, id: i64, code: i64, out: u8[>..]&) {
    let k = h2_find(c, id);
    if k >= 0 { h2_free(c, k); }
    h2_remember_reset(c, id);
    if c.state != C2_CLOSED { h2_rst(out, id, code); }
}

// A stream error (§5.4.2) on a message the peer sent.
fn h2_stream_error(c: H2Conn&, id: i64, code: i64, used: i64, out: u8[>..]&) -> H2Event {
    h2_reset(c, id, code, out);
    var ev = h2_event(EV2_RESET, used);
    ev.stream = id;
    ev.code = code;
    ev.local = true;
    return ev;
}

// One side of stream k ended.
fn h2_end_remote(c: H2Conn&, k: i64) {
    if c.streams[k].state == ST2_HALF_LOCAL { h2_free(c, k); }
    else { c.streams[k].state = ST2_HALF_REMOTE; }
}

fn h2_end_local(c: H2Conn&, k: i64) {
    if c.streams[k].state == ST2_HALF_REMOTE { h2_free(c, k); }
    else { c.streams[k].state = ST2_HALF_LOCAL; }
}

// Whether stream id is one the peer may still send on.
fn h2_stream_open(c: const H2Conn&, id: i64) -> bool {
    let k = h2_find(c, id);
    return k >= 0 && (c.streams[k].state == ST2_OPEN || c.streams[k].state == ST2_HALF_LOCAL);
}

// --- Fields --------------------------------------------------------------------

// RFC 9113 §8.2.1: a name of lowercase token characters (a pseudo-header's
// colon first); a value without NUL, CR or LF, and not starting or ending
// with whitespace.
fn h2_name_ok(n: const u8[:]) -> bool {
    if n.len == 0 { return false; }
    for i in n.len {
        let ch = n[i];
        if i == 0 && ch == ':' { continue; }
        if ch >= 'A' && ch <= 'Z' { return false; }
        if !is_tchar(ch) { return false; }
    }
    return true;
}

fn h2_value_ok(v: const u8[:]) -> bool {
    for ch in v { if ch == 0 || ch == '\r' || ch == '\n' { return false; } }
    if v.len > 0 && (v[0] == ' ' || v[0] == '\t' || v[v.len - 1] == ' ' || v[v.len - 1] == '\t') { return false; }
    return true;
}

// A pseudo-header field's (or any field's) value from h2_read's lines.
fn h2_field(fields: const u8[:], name: const u8[:]) -> const u8[:], bool {
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        if line.len > name.len + 1 && line[name.len] == ':' && line[name.len + 1] == ' ' && eq_fold(line[..name.len], name) {
            return line[name.len + 2..], true;
        }
        if line.len == name.len + 1 && line[name.len] == ':' && eq_fold(line[..name.len], name) { return "", true; }
        pos = end + 2;
    }
    return "", false;
}

// Checks a decoded header section (§8.2, §8.3) and writes it as lines:
// pseudo-header fields first, then the rest. `kind`: 0 request, 1
// response, 2 trailers. The status of a response, or -1 if the section is
// malformed; for a request, 0.
fn h2_section(recs: const u8[:], kind: i64, lines: u8[>..]&, clen: i64&) -> i64 {
    var regular = false;
    var bad = false;
    var method: u8[>..] = [];
    var n_method = 0;
    var n_scheme = 0;
    var n_path = 0;
    var n_auth = 0;
    var n_status = 0;
    var empty_path = false;
    var status: i64 = 0;
    var auth: u8[>..] = [];
    var host: u8[>..] = [];
    var has_host = false;
    clen = -1;
    var rest: u8[>..] = [];
    each_hpack_field(recs) { n, v, s =>
        if !h2_name_ok(n) || !h2_value_ok(v) { bad = true; }
        if n.len > 0 && n[0] == ':' {
            // Pseudo-header fields: before the others, known, once each.
            if regular || kind == 2 { bad = true; }
            if kind == 0 {
                if n == ":method" { n_method++; method.clear(); method.append(v); }
                else if n == ":scheme" { n_scheme++; }
                else if n == ":path" { n_path++; if v.len == 0 { empty_path = true; } }
                else if n == ":authority" { n_auth++; auth.clear(); auth.append(v); }
                else { bad = true; }
            } else if kind == 1 {
                if n == ":status" {
                    n_status++;
                    if v.len != 3 { bad = true; }
                    var st: i64 = 0;
                    for ch in v { if ch < '0' || ch > '9' { bad = true; } else { st = st * 10 + (ch - '0') as i64; } }
                    status = st;
                } else { bad = true; }
            }
            lines.append(n);
            lines.append(": ");
            lines.append(v);
            lines.append("\r\n");
        } else {
            regular = true;
            // §8.2.2: no connection-specific fields; TE only as "trailers".
            if n == "connection" || n == "keep-alive" || n == "proxy-connection" || n == "transfer-encoding" || n == "upgrade" {
                bad = true;
            }
            if n == "te" && v != "trailers" { bad = true; }
            if n == "content-length" && kind != 2 {
                var x: i64 = 0;
                if v.len == 0 || v.len > 18 { bad = true; }
                for ch in v { if ch < '0' || ch > '9' { bad = true; } else if !bad { x = x * 10 + (ch - '0') as i64; } }
                if clen >= 0 && clen != x { bad = true; }
                clen = x;
            }
            if n == "host" { has_host = true; host.clear(); host.append(v); }
            rest.append(n);
            rest.append(": ");
            rest.append(v);
            rest.append("\r\n");
        }
    };
    if kind == 0 {
        let connect = method[..] == "CONNECT";
        if n_method != 1 || n_auth > 1 { bad = true; }
        if connect {
            // §8.5: :authority alone.
            if n_scheme != 0 || n_path != 0 || n_auth != 1 { bad = true; }
        } else {
            if n_scheme != 1 || n_path != 1 || empty_path { bad = true; }
        }
        // §8.3.1: Host and :authority the same if both are there.
        if has_host && n_auth == 1 && host[..] != auth[..] { bad = true; }
    }
    if kind == 1 && (n_status != 1 || status < 100) { bad = true; }
    lines.append(rest);
    if bad { return -1; }
    return if kind == 1 { status } else { 0 };
}

// --- Reading -------------------------------------------------------------------

// The next thing the buffer holds: one frame (a header block: all its
// frames), as an event. ERROR leaves our GOAWAY in out; frames that answer
// the peer's (SETTINGS acks, PING acks, WINDOW_UPDATEs, RST_STREAMs) go
// to out too. Header fields go to `fields` (cleared first) as lines, DATA
// is appended to `body`.
fn h2_read(c: H2Conn&, m: const u8[:], fields: u8[>..]&, body: u8[>..]&, out: u8[>..]&) -> H2Event {
    if c.state == C2_CLOSED { return h2_event(EV2_ERROR, 0); }
    if c.state == C2_PREFACE {
        let n = if m.len < H2_PREFACE.len { m.len } else { H2_PREFACE.len };
        if m[..n] != H2_PREFACE[..n] { return h2_fail(c, E2_PROTOCOL, out); }
        if n < H2_PREFACE.len { return h2_event(EV2_NEED_MORE, 0); }
        c.state = C2_SETTINGS;
        return h2_event(EV2_NONE, H2_PREFACE.len);
    }
    if m.len < 9 { return h2_event(EV2_NEED_MORE, 0); }
    let len = ((m[0] as i64) << 16) | ((m[1] as i64) << 8) | (m[2] as i64);
    let ty = m[3];
    let flags = m[4];
    let sid = get_u32(m, 5) & 0x7fffffff;
    // §4.2: past our SETTINGS_MAX_FRAME_SIZE.
    if len > c.opt.max_frame_size { return h2_fail(c, E2_FRAME_SIZE, out); }
    if m.len < 9 + len { return h2_event(EV2_NEED_MORE, 0); }
    let p = m[9..9 + len];
    let used = 9 + len;
    // The peer's first frame is SETTINGS (§3.4).
    if c.state == C2_SETTINGS && (ty != F2_SETTINGS || (flags & FL2_ACK) != 0) { return h2_fail(c, E2_PROTOCOL, out); }
    if ty == F2_DATA { return h2_read_data(c, sid, flags, p, used, body, out); }
    if ty == F2_HEADERS { return h2_read_headers(c, m, sid, flags, len, fields, out); }
    if ty == F2_PRIORITY {
        if sid == 0 { return h2_fail(c, E2_PROTOCOL, out); }
        if len != 5 { return h2_stream_error(c, sid, E2_FRAME_SIZE, used, out); }
        if (get_u32(p, 0) & 0x7fffffff) == sid { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
        return h2_event(EV2_NONE, used);
    }
    if ty == F2_RST_STREAM {
        if sid == 0 { return h2_fail(c, E2_PROTOCOL, out); }
        if len != 4 { return h2_fail(c, E2_FRAME_SIZE, out); }
        if h2_idle(c, sid) { return h2_fail(c, E2_PROTOCOL, out); }
        let k = h2_find(c, sid);
        if k < 0 { return h2_event(EV2_NONE, used); }
        // The peer's reset: frames on the stream after it are STREAM_CLOSED
        // (§5.1), unlike frames in flight on a stream we reset.
        h2_free(c, k);
        var ev = h2_event(EV2_RESET, used);
        ev.stream = sid;
        ev.code = get_u32(p, 0);
        return ev;
    }
    if ty == F2_SETTINGS { return h2_read_settings(c, sid, flags, p, used, out); }
    if ty == F2_PUSH_PROMISE {
        // A server never gets one; our clients say SETTINGS_ENABLE_PUSH 0.
        return h2_fail(c, E2_PROTOCOL, out);
    }
    if ty == F2_PING {
        if sid != 0 { return h2_fail(c, E2_PROTOCOL, out); }
        if len != 8 { return h2_fail(c, E2_FRAME_SIZE, out); }
        if (flags & FL2_ACK) != 0 { var ev = h2_event(EV2_PING, used); return ev; }
        frame_head(out, 8, F2_PING, FL2_ACK, 0);
        out.append(p);
        return h2_event(EV2_NONE, used);
    }
    if ty == F2_GOAWAY {
        if sid != 0 { return h2_fail(c, E2_PROTOCOL, out); }
        if len < 8 { return h2_fail(c, E2_FRAME_SIZE, out); }
        c.goaway_got = true;
        c.peer_last = get_u32(p, 0) & 0x7fffffff;
        var ev = h2_event(EV2_GOAWAY, used);
        ev.last_stream = c.peer_last;
        ev.code = get_u32(p, 4);
        return ev;
    }
    if ty == F2_WINDOW_UPDATE { return h2_read_window(c, sid, p, used, out); }
    if ty == F2_CONTINUATION {
        // Only after a HEADERS without END_HEADERS, which h2_read_headers takes whole.
        return h2_fail(c, E2_PROTOCOL, out);
    }
    // §4.1, §5.5: frames of unknown types are ignored.
    return h2_event(EV2_NONE, used);
}

// Whether stream id is idle: one the peer could still open (§5.1.1).
fn h2_idle(c: const H2Conn&, id: i64) -> bool {
    let peer_opens = if c.opt.server { (id & 1) == 1 } else { (id & 1) == 0 };
    if peer_opens { return id > c.last_peer; }
    return id >= c.next_id;
}

fn h2_read_settings(c: H2Conn&, sid: i64, flags: u8, p: const u8[:], used: i64, out: u8[>..]&) -> H2Event {
    if sid != 0 { return h2_fail(c, E2_PROTOCOL, out); }
    if (flags & FL2_ACK) != 0 {
        if p.len != 0 { return h2_fail(c, E2_FRAME_SIZE, out); }
        if c.settings_unacked > 0 { c.settings_unacked--; }
        return h2_event(EV2_NONE, used);
    }
    if p.len % 6 != 0 { return h2_fail(c, E2_FRAME_SIZE, out); }
    var window_changed = false;
    var i = 0;
    while i < p.len {
        let id = ((p[i] as i64) << 8) | (p[i + 1] as i64);
        let v = get_u32(p, i + 2);
        i += 6;
        if id == S2_HEADER_TABLE_SIZE {
            c.peer.header_table_size = v;
            hpack_peer_limit(c.enc, v);
        } else if id == S2_ENABLE_PUSH {
            if v > 1 { return h2_fail(c, E2_PROTOCOL, out); }
            // §6.5.2: a server may not say 1.
            if !c.opt.server && v == 1 { return h2_fail(c, E2_PROTOCOL, out); }
            c.peer.enable_push = v == 1;
        } else if id == S2_MAX_CONCURRENT_STREAMS {
            c.peer.max_concurrent_streams = v;
        } else if id == S2_INITIAL_WINDOW_SIZE {
            if v > H2_MAX_WINDOW { return h2_fail(c, E2_FLOW_CONTROL, out); }
            // §6.9.2: every stream's window moves by the change.
            let delta = v - c.peer.initial_window_size;
            for k in H2_MAX_STREAMS {
                if c.streams[k].id != 0 {
                    c.streams[k].send_window += delta;
                    if c.streams[k].send_window > H2_MAX_WINDOW { return h2_fail(c, E2_FLOW_CONTROL, out); }
                }
            }
            c.peer.initial_window_size = v;
            if delta > 0 { window_changed = true; }
        } else if id == S2_MAX_FRAME_SIZE {
            if v < 16384 || v > 16777215 { return h2_fail(c, E2_PROTOCOL, out); }
            c.peer.max_frame_size = v;
        } else if id == S2_MAX_HEADER_LIST_SIZE {
            c.peer.max_header_list_size = v;
        }
        // Others are ignored (§6.5.2).
    }
    frame_head(out, 0, F2_SETTINGS, FL2_ACK, 0);
    if c.state == C2_SETTINGS { c.state = C2_OPEN; }
    var ev = h2_event(if window_changed { EV2_WINDOW } else { EV2_NONE }, used);
    return ev;
}

fn h2_read_window(c: H2Conn&, sid: i64, p: const u8[:], used: i64, out: u8[>..]&) -> H2Event {
    if p.len != 4 { return h2_fail(c, E2_FRAME_SIZE, out); }
    let inc = get_u32(p, 0) & 0x7fffffff;
    if sid == 0 {
        if inc == 0 { return h2_fail(c, E2_PROTOCOL, out); }
        c.conn_send += inc;
        if c.conn_send > H2_MAX_WINDOW { return h2_fail(c, E2_FLOW_CONTROL, out); }
        return h2_event(EV2_WINDOW, used);
    }
    if h2_idle(c, sid) { return h2_fail(c, E2_PROTOCOL, out); }
    let k = h2_find(c, sid);
    if k < 0 { return h2_event(EV2_NONE, used); }       // closed: in flight, ignored (§6.9)
    if inc == 0 { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    c.streams[k].send_window += inc;
    if c.streams[k].send_window > H2_MAX_WINDOW { return h2_stream_error(c, sid, E2_FLOW_CONTROL, used, out); }
    var ev = h2_event(EV2_WINDOW, used);
    ev.stream = sid;
    return ev;
}

// The payload without its padding (§6.1, §6.2): start and end, or -1.
fn h2_unpad(p: const u8[:], flags: u8) -> i64, i64 {
    if (flags & FL2_PADDED) == 0 { return 0, p.len; }
    if p.len < 1 { return -1, -1; }
    let padn = p[0] as i64;
    if padn >= p.len { return -1, -1; }
    return 1, p.len - padn;
}

fn h2_read_data(c: H2Conn&, sid: i64, flags: u8, p: const u8[:], used: i64, body: u8[>..]&, out: u8[>..]&) -> H2Event {
    if sid == 0 { return h2_fail(c, E2_PROTOCOL, out); }
    let start, end = h2_unpad(p, flags);
    if start < 0 { return h2_fail(c, E2_PROTOCOL, out); }
    // The whole frame counts against the connection's window, whatever
    // becomes of the stream (§6.9).
    if p.len > c.conn_recv { return h2_fail(c, E2_FLOW_CONTROL, out); }
    c.conn_recv -= p.len;
    // What is not the application's (padding, a dead stream's data) is
    // given back at once.
    var spent = p.len - (end - start);
    let k = h2_find(c, sid);
    if k < 0 || !(c.streams[k].state == ST2_OPEN || c.streams[k].state == ST2_HALF_LOCAL) {
        h2_give_back(c, -1, p.len, out);
        if h2_idle(c, sid) { return h2_fail(c, E2_PROTOCOL, out); }
        if k >= 0 { return h2_stream_error(c, sid, E2_STREAM_CLOSED, used, out); }      // half-closed (remote)
        if h2_was_reset(c, sid) { return h2_event(EV2_NONE, used); }
        return h2_fail(c, E2_STREAM_CLOSED, out);
    }
    let s: H2Stream& = c.streams[k];
    if !s.got_head { h2_give_back(c, -1, p.len, out); return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    if p.len > s.recv_window {
        h2_give_back(c, -1, p.len, out);
        return h2_stream_error(c, sid, E2_FLOW_CONTROL, used, out);
    }
    s.recv_window -= p.len;
    s.received += end - start;
    let es = (flags & FL2_END_STREAM) != 0;
    // §8.1.1: content-length is the sum of the DATA (a response to HEAD,
    // and 204 and 304, have none).
    if (s.head_request || s.no_content) && end > start {
        h2_give_back(c, -1, p.len, out);
        return h2_stream_error(c, sid, E2_PROTOCOL, used, out);
    }
    if s.clen >= 0 && !s.head_request && !s.no_content && (s.received > s.clen || (es && s.received != s.clen)) {
        h2_give_back(c, -1, p.len, out);
        return h2_stream_error(c, sid, E2_PROTOCOL, used, out);
    }
    if spent > 0 { h2_give_back(c, k, spent, out); }
    body.append(p[start..end]);
    if es { h2_end_remote(c, k); }
    var ev = h2_event(EV2_DATA, used);
    ev.stream = sid;
    ev.end_stream = es;
    return ev;
}

// The application has used n bytes of stream id's DATA: the windows are
// opened again (WINDOW_UPDATE) once half of one is used, as Go does.
fn h2_consumed(c: H2Conn&, id: i64, n: i64, out: u8[>..]&) {
    if n <= 0 || c.state == C2_CLOSED { return; }
    h2_give_back(c, h2_find(c, id), n, out);
}

fn h2_give_back(c: H2Conn&, k: i64, n: i64, out: u8[>..]&) {
    if c.state == C2_CLOSED { return; }
    c.conn_unacked += n;
    if c.conn_unacked >= c.opt.conn_window / 2 {
        frame_head(out, 4, F2_WINDOW_UPDATE, 0, 0);
        put_u32(out, c.conn_unacked);
        c.conn_recv += c.conn_unacked;
        c.conn_unacked = 0;
    }
    if k < 0 { return; }
    let s: H2Stream& = c.streams[k];
    // A stream the peer has ended needs no more window.
    if s.state == ST2_HALF_REMOTE { return; }
    s.unacked += n;
    if s.unacked >= c.opt.stream_window / 2 {
        frame_head(out, 4, F2_WINDOW_UPDATE, 0, s.id);
        put_u32(out, s.unacked);
        s.recv_window += s.unacked;
        s.unacked = 0;
    }
}

// HEADERS and its CONTINUATIONs, once they are all in the buffer.
fn h2_read_headers(c: H2Conn&, m: const u8[:], sid: i64, flags: u8, len: i64, fields: u8[>..]&, out: u8[>..]&) -> H2Event {
    if sid == 0 { return h2_fail(c, E2_PROTOCOL, out); }
    // The block: the HEADERS frame's fragment, then each CONTINUATION's,
    // up to the frame with END_HEADERS.
    var blk: u8[>..] = [];
    let p = m[9..9 + len];
    let start, end = h2_unpad(p, flags);
    if start < 0 { return h2_fail(c, E2_PROTOCOL, out); }
    var frag_start = start;
    var prio_dep: i64 = -1;
    if (flags & FL2_PRIORITY) != 0 {
        if end - start < 5 { return h2_fail(c, E2_FRAME_SIZE, out); }
        prio_dep = get_u32(p, start) & 0x7fffffff;
        frag_start = start + 5;
    }
    blk.append(p[frag_start..end]);
    var at = 9 + len;
    var last_flags = flags;
    // The most a block may take in frames: the list limit, and room for
    // HPACK's overhead; past it the peer is flooding (CONTINUATION).
    let block_limit = c.opt.max_header_list + 16384;
    while (last_flags & FL2_END_HEADERS) == 0 {
        if m.len < at + 9 {
            if at - 9 - len > block_limit { return h2_fail(c, E2_ENHANCE_YOUR_CALM, out); }
            return h2_event(EV2_NEED_MORE, 0);
        }
        let clen = ((m[at] as i64) << 16) | ((m[at + 1] as i64) << 8) | (m[at + 2] as i64);
        let cty = m[at + 3];
        let cflags = m[at + 4];
        let csid = get_u32(m, at + 5) & 0x7fffffff;
        if cty != F2_CONTINUATION || csid != sid { return h2_fail(c, E2_PROTOCOL, out); }
        if clen > c.opt.max_frame_size { return h2_fail(c, E2_FRAME_SIZE, out); }
        if m.len < at + 9 + clen { return h2_event(EV2_NEED_MORE, 0); }
        blk.append(m[at + 9..at + 9 + clen]);
        if blk.len > block_limit { return h2_fail(c, E2_ENHANCE_YOUR_CALM, out); }
        last_flags = cflags;
        at += 9 + clen;
    }
    let used = at;
    let es = (flags & FL2_END_STREAM) != 0;
    // HPACK first, whatever becomes of the stream, to keep the table in step.
    var recs: u8[>..] = [];
    let hr = hpack_decode(c.dec, blk, c.opt.max_header_list, recs);
    if hr == HPACK_ERROR { return h2_fail(c, E2_COMPRESSION, out); }
    if prio_dep == sid { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    fields.clear();
    var k = h2_find(c, sid);
    let peer_opens = if c.opt.server { (sid & 1) == 1 } else { (sid & 1) == 0 };
    if k < 0 {
        // A new stream: the peer's to open, above the last one (§5.1.1).
        if h2_was_reset(c, sid) { return h2_event(EV2_NONE, used); }
        if !c.opt.server { return h2_fail(c, if h2_idle(c, sid) { E2_PROTOCOL } else { E2_STREAM_CLOSED }, out); }
        if !peer_opens { return h2_fail(c, E2_PROTOCOL, out); }
        if sid <= c.last_peer { return h2_fail(c, E2_STREAM_CLOSED, out); }
        c.last_peer = sid;
        if c.goaway_sent { return h2_event(EV2_NONE, used); }
        if c.active >= c.opt.max_concurrent_streams || c.active >= H2_MAX_STREAMS {
            return h2_stream_error(c, sid, E2_REFUSED_STREAM, used, out);
        }
        k = h2_new_stream(c, sid);
    } else if !(c.streams[k].state == ST2_OPEN || c.streams[k].state == ST2_HALF_LOCAL) {
        return h2_stream_error(c, sid, E2_STREAM_CLOSED, used, out);
    }
    let s: H2Stream& = c.streams[k];
    // Which section: the first is the head; after it, trailers (with
    // END_STREAM); a client's 1xx heads come before the final one.
    let trailers = s.got_head;
    if trailers && !es { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    if hr == HPACK_TOO_LARGE {
        if c.opt.server && !trailers {
            // §10.5.1: 431, as Go answers; a body still to come is
            // stopped with RST_STREAM NO_ERROR (§8.1).
            if es { h2_end_remote(c, k); }
            h2_respond(c, sid, 431, "", true, out);
            if h2_find(c, sid) >= 0 { h2_reset(c, sid, E2_NO_ERROR, out); }
            return h2_event(EV2_NONE, used);
        }
        return h2_stream_error(c, sid, E2_PROTOCOL, used, out);
    }
    var clen: i64 = -1;
    let kind: i64 = if trailers { 2 } else if c.opt.server { 0 } else { 1 };
    let status = h2_section(recs, kind, fields, clen);
    if status < 0 { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    let interim = kind == 1 && status < 200;
    if interim && es { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    if !trailers && !interim {
        s.got_head = true;
        s.clen = clen;
        if kind == 1 && (status == 204 || status == 304) { s.no_content = true; }
        if es && clen > 0 && !s.head_request && !s.no_content { return h2_stream_error(c, sid, E2_PROTOCOL, used, out); }
    }
    if trailers && s.clen >= 0 && !s.head_request && !s.no_content && s.received != s.clen {
        return h2_stream_error(c, sid, E2_PROTOCOL, used, out);
    }
    if es { h2_end_remote(c, k); }
    var ev = h2_event(EV2_HEADERS, used);
    ev.stream = sid;
    ev.end_stream = es;
    ev.trailers = trailers;
    ev.interim = interim;
    ev.status = if kind == 1 { status } else { 0 };
    return ev;
}

// --- Writing -------------------------------------------------------------------

fn h2_encode_fields(c: H2Conn&, fields: const u8[:], blk: u8[>..]&) {
    var name: u8[>..] = [];
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        let colon = position(line, ':');
        if colon > 0 {
            name.clear();
            for ch in line[..colon] { name.push(lower(ch)); }
            let v = trim_ows(line[colon + 1..]);
            let skip = name[..] == "connection" || name[..] == "keep-alive" || name[..] == "proxy-connection" ||
                       name[..] == "transfer-encoding" || name[..] == "upgrade" || name[..] == "host" ||
                       (name[..] == "te" && !eq_fold(v, "trailers"));
            // Credentials and cookies are never indexed, as Go does for
            // Authorization and short cookies.
            let sensitive = name[..] == "authorization" || name[..] == "proxy-authorization" ||
                            (name[..] == "cookie" && v.len < 20);
            if !skip {
                if name[..] == "cookie" {
                    // §8.2.3: each cookie its own field, for better compression.
                    each_split(v, ';') {
                        let one = trim_ows(it);
                        if one.len > 0 { hpack_field(c.enc, blk, "cookie", one, one.len < 20); }
                    };
                } else {
                    hpack_field(c.enc, blk, name, v, sensitive);
                }
            }
        }
        pos = end + 2;
    }
}

// Whether the client may open another stream: the peer's limit, ours, and
// no GOAWAY either way.
fn h2_can_open(c: const H2Conn&) -> bool {
    return c.state != C2_CLOSED && !c.goaway_got && !c.goaway_sent && c.active < c.peer.max_concurrent_streams &&
           c.active < H2_MAX_STREAMS && c.next_id <= H2_MAX_WINDOW;
}

// A client's request: a new stream (its id, or -1 if none can be opened),
// its HEADERS. `fields` as "Name: value\r\n" lines; `head` for a HEAD
// request (its response has no content).
fn h2_request(c: H2Conn&, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:],
              fields: const u8[:], end_stream: bool, out: u8[>..]&) -> i64 {
    if c.opt.server || !h2_can_open(c) { return -1; }
    let sid = c.next_id;
    c.next_id += 2;
    let k = h2_new_stream(c, sid);
    if k < 0 { return -1; }
    c.streams[k].head_request = method == "HEAD";
    var blk: u8[>..] = [];
    hpack_begin(c.enc, blk);
    hpack_field(c.enc, blk, ":method", method, false);
    if method != "CONNECT" {
        hpack_field(c.enc, blk, ":scheme", scheme, false);
        hpack_field(c.enc, blk, ":path", path, false);
    }
    hpack_field(c.enc, blk, ":authority", authority, false);
    h2_encode_fields(c, fields, blk);
    h2_frames_of(sid, blk, end_stream, out);
    if end_stream { h2_end_local(c, k); }
    return sid;
}

fn h2_frames_of(sid: i64, blk: const u8[:], end_stream: bool, out: u8[>..]&) {
    let max: i64 = 16384;
    var at = 0;
    var first = true;
    while first || at < blk.len {
        let n = if blk.len - at > max { max } else { blk.len - at };
        var flags: u8 = 0;
        if at + n >= blk.len { flags = flags | FL2_END_HEADERS; }
        if first && end_stream { flags = flags | FL2_END_STREAM; }
        frame_head(out, n, if first { F2_HEADERS } else { F2_CONTINUATION }, flags, sid);
        out.append(blk[at..at + n]);
        at += n;
        first = false;
    }
}

// A server's response head on stream sid. False if the stream is gone.
fn h2_respond(c: H2Conn&, sid: i64, status: i64, fields: const u8[:], end_stream: bool, out: u8[>..]&) -> bool {
    let k = h2_find(c, sid);
    if k < 0 || c.state == C2_CLOSED || c.streams[k].state == ST2_HALF_LOCAL { return false; }
    var st: u8[>..] = [];
    format(st, status);
    var blk: u8[>..] = [];
    hpack_begin(c.enc, blk);
    hpack_field(c.enc, blk, ":status", st, false);
    h2_encode_fields(c, fields, blk);
    h2_frames_of(sid, blk, end_stream && status >= 200, out);
    if end_stream && status >= 200 { h2_end_local(c, k); }
    return true;
}

// Trailer fields, ending our side of the stream.
fn h2_trailers(c: H2Conn&, sid: i64, fields: const u8[:], out: u8[>..]&) -> bool {
    let k = h2_find(c, sid);
    if k < 0 || c.state == C2_CLOSED || c.streams[k].state == ST2_HALF_LOCAL { return false; }
    var blk: u8[>..] = [];
    hpack_begin(c.enc, blk);
    h2_encode_fields(c, fields, blk);
    h2_frames_of(sid, blk, true, out);
    h2_end_local(c, k);
    return true;
}

// What may be sent on stream sid now: its window and the connection's.
fn h2_send_room(c: const H2Conn&, sid: i64) -> i64 {
    let k = h2_find(c, sid);
    if k < 0 || c.state == C2_CLOSED { return 0; }
    let w = c.streams[k].send_window;
    let room = if w < c.conn_send { w } else { c.conn_send };
    return if room < 0 { 0 } else { room };
}

// Sends as much of `data` on stream sid as the windows allow, in frames of
// 16 KiB at most, with END_STREAM after the last if `end_stream` and all
// of it went: how many bytes went, or -1 if the stream is gone.
fn h2_data(c: H2Conn&, sid: i64, data: const u8[:], end_stream: bool, out: u8[>..]&) -> i64 {
    let k = h2_find(c, sid);
    if k < 0 || c.state == C2_CLOSED || c.streams[k].state == ST2_HALF_LOCAL { return -1; }
    var sent = 0;
    let max: i64 = 16384;
    while sent < data.len {
        let room = h2_send_room(c, sid);
        if room <= 0 { break; }
        var n = data.len - sent;
        if n > room { n = room; }
        if n > max { n = max; }
        let last = sent + n == data.len;
        frame_head(out, n, F2_DATA, if last && end_stream { FL2_END_STREAM } else { 0 }, sid);
        out.append(data[sent..sent + n]);
        c.streams[k].send_window -= n;
        c.conn_send -= n;
        sent += n;
    }
    if end_stream && sent == data.len {
        if data.len == 0 { frame_head(out, 0, F2_DATA, FL2_END_STREAM, sid); }
        h2_end_local(c, k);
    }
    return sent;
}

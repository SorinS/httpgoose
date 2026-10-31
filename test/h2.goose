// http.h2: a client and a server of this package talking in memory
// (requests, responses, bodies past the flow-control windows, CONTINUATION,
// trailers, 1xx, HEAD), and frames made by hand for what each side must
// refuse (RFC 9113 §4 to §8). h2spec runs the server's side against
// goose-httpd (scripts/h2spec.py); interop.py the rest.

import std;
import http from "..";
import http.hpack;
import http.h1;
import http.h2;

var failures = 0;

fn check(what: const u8[:], got: const u8[:], want: const u8[:]) {
    if got != want {
        print("FAIL ", what, ":\n  got  '", got, "'\n  want '", want, "'");
        failures++;
    }
}

fn check_int(what: const u8[:], got: i64, want: i64) {
    if got != want {
        print("FAIL ", what, ": got ", got, " want ", want);
        failures++;
    }
}

// Reads everything in `buf` (what the other side sent), logging the
// events: "H sid [es] [tr] [1xx]: fields", "D sid n [es]", "R sid code
// [local]", "G last code", "W sid", "E code", "P". DATA is appended to
// body; with `consume`, given back at once.
fn drain(c: http::H2Conn&, buf: u8[>..]&, out: u8[>..]&, log: u8[>..]&, body: u8[>..]&, consume: bool) {
    var fields: u8[>..] = [];
    while true {
        let before = body.len;
        let ev = http::h2_read(c, buf, fields, body, out);
        var rest: u8[>..] = [];
        rest.append(buf[ev.used..]);
        buf.clear();
        buf.append(rest);
        if ev.kind == http::EV2_NEED_MORE { return; }
        if ev.kind == http::EV2_HEADERS {
            log.append("H ");
            format(log, ev.stream);
            if ev.end_stream { log.append(" es"); }
            if ev.trailers { log.append(" tr"); }
            if ev.interim { log.append(" 1xx"); }
            log.append(": ");
            for ch in fields { if ch == '\r' { continue; } log.push(if ch == '\n' { '|' } else { ch }); }
            log.push('\n');
        } else if ev.kind == http::EV2_DATA {
            log.append("D ");
            format(log, ev.stream);
            log.push(' ');
            format(log, body.len - before);
            if ev.end_stream { log.append(" es"); }
            log.push('\n');
            if consume { http::h2_consumed(c, ev.stream, body.len - before, out); }
        } else if ev.kind == http::EV2_RESET {
            log.append("R ");
            format(log, ev.stream);
            log.push(' ');
            format(log, ev.code);
            if ev.local { log.append(" local"); }
            log.push('\n');
        } else if ev.kind == http::EV2_GOAWAY {
            log.append("G ");
            format(log, ev.last_stream);
            log.push(' ');
            format(log, ev.code);
            log.push('\n');
        } else if ev.kind == http::EV2_WINDOW {
            // Not logged: when they come depends on the windows.
        } else if ev.kind == http::EV2_ERROR {
            log.append("E ");
            format(log, ev.code);
            log.push('\n');
            return;
        } else if ev.kind == http::EV2_PING {
            log.append("P\n");
        }
    }
}

// The frames in `out` as "TYPE sid flags len" lines, for checking what a
// side sent.
fn frames(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var p = 0;
    if b.len >= 24 && b[..24] == http::H2_PREFACE { out.append("PREFACE\n"); p = 24; }
    let names = ["DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"];
    while p + 9 <= b.len {
        let len = ((b[p] as i64) << 16) | ((b[p + 1] as i64) << 8) | (b[p + 2] as i64);
        let ty = b[p + 3] as i64;
        out.append(if ty < 10 { names[ty] } else { "?" });
        out.push(' ');
        format(out, http::get_u32(b, p + 5) & 0x7fffffff);
        out.push(' ');
        format(out, b[p + 4]);
        out.push(' ');
        format(out, len);
        if ty == 3 || ty == 8 { out.push(' '); format(out, http::get_u32(b, p + 9)); }
        if ty == 7 { out.push(' '); format(out, http::get_u32(b, p + 9)); out.push(' '); format(out, http::get_u32(b, p + 13)); }
        out.push('\n');
        p += 9 + len;
    }
    return out;
}

fn frame(out: u8[>..]&, ty: u8, flags: u8, sid: i64, payload: const u8[:]) {
    http::frame_head(out, payload.len, ty, flags, sid);
    out.append(payload);
}

fn u32b(v: i64) -> u8[>..] {
    var o: u8[>..] = [];
    http::put_u32(o, v);
    return o;
}

// A header block of raw fields ("name\tvalue" lines), as a peer's encoder
// would make it, no Huffman needed.
fn raw_block(t: http::HpackTable&, lines: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    each_split(lines, '\n') {
        let tab = position(it, '\t');
        if tab > 0 { http::hpack_field(t, b, it[..tab], it[tab + 1..], false); }
    };
    return b;
}

// A server, past the preface and SETTINGS exchange; `out` cleared.
fn server_ready(s: http::H2Conn&, buf: u8[>..]&, out: u8[>..]&) {
    var cl = http::h2_conn(http::h2_client_options());
    var cout: u8[>..] = [];
    http::h2_start(cl, cout);
    http::h2_start(s, out);
    buf.append(cout);
    var log: u8[>..] = [];
    var body: u8[>..] = [];
    drain(s, buf, out, log, body, true);
    out.clear();
}

fn basics() {
    var cl = http::h2_conn(http::h2_client_options());
    var sv = http::h2_conn(http::h2_server_options());
    var to_s: u8[>..] = [];
    var to_c: u8[>..] = [];
    var clog: u8[>..] = [];
    var slog: u8[>..] = [];
    var cbody: u8[>..] = [];
    var sbody: u8[>..] = [];
    http::h2_start(cl, to_s);
    check("client's start", frames(to_s), "PREFACE\nSETTINGS 0 0 30\nWINDOW_UPDATE 0 0 4 16711681\n");
    http::h2_start(sv, to_c);
    check("server's start", frames(to_c), "SETTINGS 0 0 30\nWINDOW_UPDATE 0 0 4 983041\n");
    drain(sv, to_s, to_c, slog, sbody, true);
    drain(cl, to_c, to_s, clog, cbody, true);
    drain(sv, to_s, to_c, slog, sbody, true);
    check_int("settings acked", sv.settings_unacked + cl.settings_unacked, 0);
    check_int("client sees the server's streams", cl.peer.max_concurrent_streams, 250);
    // A GET.
    let sid = http::h2_request(cl, "GET", "https", "example.com", "/a?b", "Accept: */*\r\nUser-Agent: t\r\nConnection: keep-alive\r\nHost: x\r\n", true, to_s);
    check_int("first stream", sid, 1);
    drain(sv, to_s, to_c, slog, sbody, true);
    check("request", slog, "H 1 es: :method: GET|:scheme: https|:path: /a?b|:authority: example.com|accept: */*|user-agent: t|\n");
    slog.clear();
    http::h2_respond(sv, 1, 200, "Content-Type: text/plain\r\nContent-Length: 5\r\n", false, to_c);
    check_int("data sent", http::h2_data(sv, 1, "hello", true, to_c), 5);
    drain(cl, to_c, to_s, clog, cbody, true);
    check("response", clog, "H 1: :status: 200|content-type: text/plain|content-length: 5|\nD 1 5 es\n");
    check("response body", cbody, "hello");
    check_int("streams closed both sides", sv.active + cl.active, 0);
    clog.clear();
    cbody.clear();
    // A POST of 300 KB through windows of 64 KB: the server gives the
    // window back as it reads.
    var small = http::h2_server_options();
    small.stream_window = 65535;
    small.conn_window = 65535;
    var cl2 = http::h2_conn(http::h2_client_options());
    var sv2 = http::h2_conn(small);
    to_s.clear();
    to_c.clear();
    http::h2_start(cl2, to_s);
    http::h2_start(sv2, to_c);
    drain(sv2, to_s, to_c, slog, sbody, true);
    drain(cl2, to_c, to_s, clog, cbody, true);
    drain(sv2, to_s, to_c, slog, sbody, true);
    var data: u8[>..] = [];
    for k in 300000 { data.push(((k * 7) % 251) as! u8); }
    let s2 = http::h2_request(cl2, "POST", "https", "h", "/up", "Content-Length: 300000\r\n", false, to_s);
    var sent = 0;
    var rounds = 0;
    while sent < data.len && rounds < 100 {
        rounds++;
        let n = http::h2_data(cl2, s2, data[sent..], true, to_s);
        sent += n;
        drain(sv2, to_s, to_c, slog, sbody, true);
        drain(cl2, to_c, to_s, clog, cbody, true);
    }
    check_int("all sent", sent, 300000);
    check_int("in several rounds", if rounds > 4 { 1 } else { 0 }, 1);
    check("all received", sbody, data);
    check_int("no window left over the limit", if sv2.conn_recv <= 65535 { 1 } else { 0 }, 1);
    // Headers past a frame: CONTINUATION.
    var big: u8[>..] = [];
    big.append("X-Big: ");
    for k in 40000 { big.push(('a' as i64 + (k * 31 + k / 7) % 26) as! u8); }
    big.append("\r\n");
    to_s.clear();
    let s3 = http::h2_request(cl, "GET", "https", "example.com", "/big", big, true, to_s);
    let fr = frames(to_s);
    check_int("HEADERS then CONTINUATIONs", if find(fr, "HEADERS 3 1 16384") >= 0 && find(fr, "CONTINUATION 3 4 ") >= 0 { 1 } else { 0 }, 1);
    // Only part of it in the buffer: nothing yet.
    var part: u8[>..] = [];
    part.append(to_s[..to_s.len - 10]);
    var fields: u8[>..] = [];
    var b: u8[>..] = [];
    var o: u8[>..] = [];
    let ev = http::h2_read(sv, part, fields, b, o);
    check_int("a block not all here", ev.kind as i64, http::EV2_NEED_MORE as i64);
    slog.clear();
    drain(sv, to_s, to_c, slog, sbody, true);
    check_int("the big field whole", if find(slog, str("|x-big: ", big[7..big.len - 2], "|")) > 0 { 1 } else { 0 }, 1);
    // Trailers, 1xx, HEAD.
    slog.clear();
    to_s.clear();
    let s5 = http::h2_request(cl, "PUT", "https", "example.com", "/t", "TE: trailers\r\n", false, to_s);
    http::h2_data(cl, s5, "abc", false, to_s);
    http::h2_trailers(cl, s5, "X-Checksum: 1\r\n", to_s);
    drain(sv, to_s, to_c, slog, sbody, true);
    check("trailers", slog, "H 5: :method: PUT|:scheme: https|:path: /t|:authority: example.com|te: trailers|\nD 5 3\nH 5 es tr: x-checksum: 1|\n");
    clog.clear();
    to_c.clear();
    http::h2_respond(sv, 5, 103, "Link: </s.css>\r\n", false, to_c);
    http::h2_respond(sv, 5, 204, "", true, to_c);
    drain(cl, to_c, to_s, clog, cbody, true);
    check("1xx then 204", clog, "H 5 1xx: :status: 103|link: </s.css>|\nH 5 es: :status: 204|\n");
    clog.clear();
    to_s.clear();
    let s7 = http::h2_request(cl, "HEAD", "https", "example.com", "/", "", true, to_s);
    drain(sv, to_s, to_c, slog, sbody, true);
    to_c.clear();
    http::h2_respond(sv, s7, 200, "Content-Length: 1234\r\n", true, to_c);
    drain(cl, to_c, to_s, clog, cbody, true);
    check("HEAD's content-length without content", clog, "H 7 es: :status: 200|content-length: 1234|\n");
}

// What a server does with a client's frames after the preface: the frames
// it sends back and its events.
fn server_on(opt: http::H2Options, client_frames: const u8[:], frames_out: u8[>..]&, log: u8[>..]&) {
    var sv = http::h2_conn(opt);
    var buf: u8[>..] = [];
    var out: u8[>..] = [];
    server_ready(sv, buf, out);
    buf.append(client_frames);
    var body: u8[>..] = [];
    drain(sv, buf, out, log, body, true);
    frames_out.append(frames(out));
}

fn server_errors() {
    let opt = http::h2_server_options();
    var t = http::hpack_table(4096);
    let get = "\t\n:method\tGET\n:scheme\thttps\n:path\t/\n:authority\th\n";
    fn case_(what: const u8[:], f: const u8[:], want_frames: const u8[:], want_log: const u8[:]) {
        var fo: u8[>..] = [];
        var lg: u8[>..] = [];
        server_on(opt, f, fo, lg);
        check(str(what, ": frames"), fo, want_frames);
        check(str(what, ": events"), lg, want_log);
    }
    fn hdr(sid: i64, flags: u8, lines: const u8[:]) -> u8[>..] {
        var tt = http::hpack_table(4096);
        var f: u8[>..] = [];
        frame(f, http::F2_HEADERS, flags, sid, raw_block(tt, lines));
        return f;
    }
    // §8.2.1, §8.3: malformed requests are stream errors.
    case_("an uppercase name", hdr(1, 5, str(get, "X-Up\t1\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("a connection field", hdr(1, 5, str(get, "connection\tclose\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("te other than trailers", hdr(1, 5, str(get, "te\tgzip\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("no :path", hdr(1, 5, ":method\tGET\n:scheme\thttps\n:authority\th\n"), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("an empty :path", hdr(1, 5, ":method\tGET\n:scheme\thttps\n:path\t\n"), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("a pseudo-header after a field", hdr(1, 5, ":method\tGET\n:scheme\thttps\nx\t1\n:path\t/\n"), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("an unknown pseudo-header", hdr(1, 5, str(get, ":x\t1\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_(":status in a request", hdr(1, 5, str(get, ":status\t200\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("two :method", hdr(1, 5, str(":method\tPOST\n", get)), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("Host other than :authority", hdr(1, 5, str(get, "host\tother\n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("a value with a trailing space", hdr(1, 5, str(get, "x\tv \n")), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("CONNECT with :path", hdr(1, 5, ":method\tCONNECT\n:authority\th:443\n:path\t/\n"), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    case_("CONNECT", hdr(1, 4, ":method\tCONNECT\n:authority\th:443\n"), "", "H 1: :method: CONNECT|:authority: h:443|\n");
    // content-length against the DATA.
    var cl: u8[>..] = [];
    cl.append(hdr(1, 4, str(get, "content-length\t3\n")));
    frame(cl, http::F2_DATA, 1, 1, "ab");
    case_("content-length more than the data", cl, "RST_STREAM 1 0 4 1\n", "H 1: :method: GET|:scheme: https|:path: /|:authority: h|content-length: 3|\nR 1 1 local\n");
    var cl2: u8[>..] = [];
    cl2.append(hdr(1, 4, str(get, "content-length\t1\n")));
    frame(cl2, http::F2_DATA, 0, 1, "ab");
    case_("data past content-length", cl2, "RST_STREAM 1 0 4 1\n", "H 1: :method: GET|:scheme: https|:path: /|:authority: h|content-length: 1|\nR 1 1 local\n");
    // Connection errors.
    var d0: u8[>..] = [];
    frame(d0, http::F2_DATA, 0, 0, "x");
    case_("DATA on stream 0", d0, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var even: u8[>..] = [];
    even.append(hdr(2, 5, get));
    case_("an even stream from a client", even, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var down: u8[>..] = [];
    down.append(hdr(5, 5, get));
    down.append(hdr(3, 5, get));
    case_("a stream below the last", down, "GOAWAY 0 0 8 5 5\n", "H 5 es: :method: GET|:scheme: https|:path: /|:authority: h|\nE 5\n");
    var pp: u8[>..] = [];
    frame(pp, http::F2_PUSH_PROMISE, 4, 1, u32b(2));
    case_("PUSH_PROMISE from a client", pp, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var sl: u8[>..] = [];
    frame(sl, http::F2_SETTINGS, 0, 0, "12345");
    case_("SETTINGS of 5 bytes", sl, "GOAWAY 0 0 8 0 6\n", "E 6\n");
    var sa: u8[>..] = [];
    frame(sa, http::F2_SETTINGS, 1, 0, "123456");
    case_("SETTINGS ack with a payload", sa, "GOAWAY 0 0 8 0 6\n", "E 6\n");
    var sw: u8[>..] = [];
    var swp: u8[>..] = [];
    swp.push(0); swp.push(4); swp.append(u32b(0x80000000));
    frame(sw, http::F2_SETTINGS, 0, 0, swp);
    case_("an initial window past 2^31 - 1", sw, "GOAWAY 0 0 8 0 3\n", "E 3\n");
    var sf: u8[>..] = [];
    var sfp: u8[>..] = [];
    sfp.push(0); sfp.push(5); sfp.append(u32b(16383));
    frame(sf, http::F2_SETTINGS, 0, 0, sfp);
    case_("a max frame size below 16384", sf, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var w0: u8[>..] = [];
    frame(w0, http::F2_WINDOW_UPDATE, 0, 0, u32b(0));
    case_("a WINDOW_UPDATE of 0", w0, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var wo: u8[>..] = [];
    frame(wo, http::F2_WINDOW_UPDATE, 0, 0, u32b(0x7fffffff));
    case_("the connection's window past 2^31 - 1", wo, "GOAWAY 0 0 8 0 3\n", "E 3\n");
    var ws: u8[>..] = [];
    ws.append(hdr(1, 4, get));
    frame(ws, http::F2_WINDOW_UPDATE, 0, 1, u32b(0x7fffffff));
    case_("a stream's window past 2^31 - 1", ws, "RST_STREAM 1 0 4 3\n", "H 1: :method: GET|:scheme: https|:path: /|:authority: h|\nR 1 3 local\n");
    var ci: u8[>..] = [];
    var tt = http::hpack_table(4096);
    frame(ci, http::F2_HEADERS, 1, 1, raw_block(tt, get));
    frame(ci, http::F2_DATA, 0, 1, "x");
    case_("a frame inside a header block", ci, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var co: u8[>..] = [];
    frame(co, http::F2_CONTINUATION, 4, 1, "");
    case_("CONTINUATION alone", co, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var big: u8[>..] = [];
    for k in 16385 { big.push(0); }
    var bf: u8[>..] = [];
    frame(bf, http::F2_DATA, 0, 1, big);
    case_("a frame past SETTINGS_MAX_FRAME_SIZE", bf, "GOAWAY 0 0 8 0 6\n", "E 6\n");
    var bad_pad: u8[>..] = [];
    bad_pad.append(hdr(1, 4, get));
    frame(bad_pad, http::F2_DATA, 8, 1, "\x05abc");
    case_("padding past the frame", bad_pad, "GOAWAY 0 0 8 1 1\n", "H 1: :method: GET|:scheme: https|:path: /|:authority: h|\nE 1\n");
    var hpe: u8[>..] = [];
    frame(hpe, http::F2_HEADERS, 5, 1, "\x80");
    case_("HPACK index 0", hpe, "GOAWAY 0 0 8 0 9\n", "E 9\n");
    var rst0: u8[>..] = [];
    frame(rst0, http::F2_RST_STREAM, 0, 9, u32b(8));
    case_("RST_STREAM on an idle stream", rst0, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var dc: u8[>..] = [];
    dc.append(hdr(1, 5, get));
    frame(dc, http::F2_DATA, 1, 1, "x");
    case_("DATA after END_STREAM", dc, "RST_STREAM 1 0 4 5\n", "H 1 es: :method: GET|:scheme: https|:path: /|:authority: h|\nR 1 5 local\n");
    var pr: u8[>..] = [];
    var prp: u8[>..] = [];
    prp.append(u32b(1));
    prp.push(16);
    frame(pr, http::F2_PRIORITY, 0, 1, prp);
    case_("PRIORITY on itself", pr, "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    var unk: u8[>..] = [];
    frame(unk, 0x20, 0, 0, "abc");
    var ping: u8[>..] = [];
    frame(ping, http::F2_PING, 0, 0, "12345678");
    unk.append(ping);
    case_("an unknown frame, then a PING", unk, "PING 0 1 8\n", "");
    // Limits: streams past the server's, and a list past its limit.
    var lim = http::h2_server_options();
    lim.max_concurrent_streams = 2;
    var three: u8[>..] = [];
    var t3 = http::hpack_table(4096);
    frame(three, http::F2_HEADERS, 4, 1, raw_block(t3, get));
    frame(three, http::F2_HEADERS, 4, 3, raw_block(t3, get));
    frame(three, http::F2_HEADERS, 4, 5, raw_block(t3, get));
    var fo: u8[>..] = [];
    var lg: u8[>..] = [];
    server_on(lim, three, fo, lg);
    check("a third stream refused", fo, "RST_STREAM 5 0 4 7\n");
    var tl = http::h2_server_options();
    tl.max_header_list = 200;
    var huge: u8[>..] = [];
    var vv: u8[>..] = [];
    for k in 300 { vv.push('v'); }
    huge.append(hdr(1, 5, str(get, "x\t", vv, "\n")));
    fo.clear();
    lg.clear();
    server_on(tl, huge, fo, lg);
    check("a list past the limit: 431", fo, "HEADERS 1 5 5\n");
}

// The client's side: what it refuses from a server.
fn client_errors() {
    fn client_case(what: const u8[:], server_frames: const u8[:], want_frames: const u8[:], want_log: const u8[:]) {
        var cl = http::h2_conn(http::h2_client_options());
        var out: u8[>..] = [];
        http::h2_start(cl, out);
        var sv = http::h2_conn(http::h2_server_options());
        var sout: u8[>..] = [];
        http::h2_start(sv, sout);
        var log: u8[>..] = [];
        var body: u8[>..] = [];
        drain(cl, sout, out, log, body, true);
        out.clear();
        http::h2_request(cl, "GET", "https", "h", "/", "", true, out);
        out.clear();
        var buf: u8[>..] = [];
        buf.append(server_frames);
        drain(cl, buf, out, log, body, true);
        check(str(what, ": frames"), frames(out), want_frames);
        check(str(what, ": events"), log, want_log);
    }
    fn resp(lines: const u8[:], flags: u8) -> u8[>..] {
        var t = http::hpack_table(4096);
        var f: u8[>..] = [];
        frame(f, http::F2_HEADERS, flags, 1, raw_block(t, lines));
        return f;
    }
    client_case("no :status", resp("x\t1\n", 5), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    client_case("a bad :status", resp(":status\t2x0\n", 5), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    client_case("a request pseudo-header", resp(":status\t200\n:path\t/\n", 5), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    client_case("a 1xx ending the stream", resp(":status\t100\n", 5), "RST_STREAM 1 0 4 1\n", "R 1 1 local\n");
    client_case("a 200", resp(":status\t200\n", 5), "", "H 1 es: :status: 200|\n");
    var pp: u8[>..] = [];
    frame(pp, http::F2_PUSH_PROMISE, 4, 1, u32b(2));
    client_case("PUSH_PROMISE (push is off)", pp, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var ep: u8[>..] = [];
    var epp: u8[>..] = [];
    epp.push(0); epp.push(2); epp.append(u32b(1));
    frame(ep, http::F2_SETTINGS, 0, 0, epp);
    client_case("ENABLE_PUSH 1 from a server", ep, "GOAWAY 0 0 8 0 1\n", "E 1\n");
    var hs: u8[>..] = [];
    hs.append(resp(":status\t200\n", 5));
    hs.append(resp(":status\t200\n", 5));
    client_case("HEADERS on a closed stream", hs, "GOAWAY 0 0 8 0 5\n", "H 1 es: :status: 200|\nE 5\n");
    var ga: u8[>..] = [];
    var gp: u8[>..] = [];
    gp.append(u32b(0));
    gp.append(u32b(0));
    frame(ga, http::F2_GOAWAY, 0, 0, gp);
    client_case("GOAWAY", ga, "", "G 0 0\n");
}

fn main() {
    basics();
    server_errors();
    client_errors();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("h2: all passed");
}

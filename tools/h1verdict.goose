// h1verdict: what this package's HTTP/1.1 parsing makes of each request
// in a cases file (one hex-encoded request a line), in h1oracle's format:
// "ok KIND LENGTH BODYHEX", "bodyerr KIND", "status N", or "noresponse"
// for a head that never ends. For scripts/h1_differential.py.
//
//	goose tools/h1verdict.goose -- cases.txt

import std;
import os;
import http from "..";
import http.h1;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((http::hex_value(s[i]) * 16 + http::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn kind_name(k: u8) -> const u8[:] {
    if k == http::BODY_CHUNKED { return "chunked"; }
    if k == http::BODY_LENGTH { return "length"; }
    return "none";
}

fn verdict(m: const u8[:], out: u8[>..]&) {
    let lim = http::default_limits();
    let h, n = http::parse_request(m, lim);
    if n == http::NEED_MORE { out.append("noresponse"); return; }
    if n < 0 { out.append("status "); format(out, -n); return; }
    let e = http::check_request(m, h);
    if e != 0 { out.append("status "); format(out, -e); return; }
    let fr, ef = http::request_framing(m, h);
    if ef != 0 { out.append("status "); format(out, -ef); return; }
    var body: u8[>..] = [];
    let rest = m[n..];
    if fr.kind == http::BODY_LENGTH {
        if rest.len < fr.length { out.append("bodyerr length"); return; }
        body.append(rest[..fr.length]);
    } else if fr.kind == http::BODY_CHUNKED {
        var d = http::chunked_decoder();
        var trailer: u8[>..] = [];
        let k = http::chunked_feed(d, lim, rest, body, trailer);
        if k < 0 || !http::chunked_done(d) { out.append("bodyerr chunked"); return; }
    }
    out.append("ok ");
    out.append(kind_name(fr.kind));
    out.push(' ');
    format(out, body.len);
    out.push(' ');
    for c in body { format_uint(out, c, 16, 2, '0'); }
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: h1verdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("h1verdict: cannot read ", a[1]); exit(1); }
    var out: u8[>..] = [];
    each_split(data, '\n') {
        let line = trim(it);
        if line.len > 0 {
            verdict(unhex(line), out);
            out.push('\n');
        }
    };
    write_stdout(out);
    flush_stdout();
}

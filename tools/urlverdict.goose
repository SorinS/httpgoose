// urlverdict: what this package's url module makes of each case of a cases
// file, in urloracle's format (two lines a case: the reference parsed,
// then resolved against the base). For scripts/url_differential.py.
//
//	goose tools/urlverdict.goose -- cases.txt

import std;
import os;
import http from "..";
import http.url;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        out.push((http::url_hex(s[i]) * 16 + http::url_hex(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn h(out: u8[>..]&, s: const u8[:]) {
    out.push(' ');
    if s.len == 0 { out.push('-'); return; }
    for c in s { format_uint(out, c, 16, 2, '0'); }
}

fn b(out: u8[>..]&, v: bool) { out.append(if v { " 1" } else { " 0" }); }

fn decoded(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    http::path_unescape(out, s);
    return out;
}

fn parts(u: const http::Url&, out: u8[>..]&) {
    out.append("ok");
    h(out, http::url_scheme(u));
    h(out, if u.opaque { http::url_path(u) } else { "" });
    b(out, u.has_user);
    h(out, http::url_username(u));
    b(out, u.has_password);
    h(out, http::url_password(u));
    h(out, http::url_hostname(u));
    h(out, http::url_port_text(u));
    let p = decoded(if u.opaque { "" } else { http::url_path(u) });
    h(out, p);
    b(out, u.has_query);
    h(out, http::url_query(u));
    let f = decoded(http::url_fragment(u));
    h(out, f);
    out.push('\n');
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: urlverdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("urlverdict: cannot read ", a[1]); exit(1); }
    var out: u8[>..] = [];
    each_split(data, '\n') {
        let line = trim(it);
        let sp = position(line, ' ');
        if sp > 0 {
            let r = unhex(line[sp + 1..]);
            let ru, re = http::url_parse(r);
            if re != 0 { out.append("err\n"); } else { parts(ru, out); }
            if line[..sp] == "-" {
                out.append("-\n");
            } else {
                let bu, be = http::url_parse(unhex(line[..sp]));
                if be != 0 {
                    out.append("err\n");
                } else {
                    let x, xe = http::url_resolve(bu, r);
                    if xe != 0 { out.append("err\n"); } else { parts(x, out); }
                }
            }
        }
    };
    write_stdout(out);
    flush_stdout();
}

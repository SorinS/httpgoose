// hpackverdict: this package's HPACK against hpackoracle's cases, for
// scripts/hpack_differential.py.
//
//	goose tools/hpackverdict.goose -- decode cases.txt   what each block decodes to, in the cases' format
//	goose tools/hpackverdict.goose -- encode cases.txt   each decoded list encoded again, for hpackoracle check

import std;
import os;
import http from "..";
import http.hpack;
import http.h1;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        out.push((http::hex_value(s[i]) * 16 + http::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn h(out: u8[>..]&, s: const u8[:]) {
    out.push(' ');
    if s.len == 0 { out.push('-'); return; }
    for c in s { format_uint(out, c, 16, 2, '0'); }
}

fn main() {
    let a = args();
    if a.len < 3 { write_stderr("usage: hpackverdict decode|encode cases.txt\n"); exit(2); }
    let mode = a[1];
    var text: u8[>..] = [];
    if !read_file(a[2], text) { write_stderr("hpackverdict: cannot read the cases\n"); exit(2); }
    var out: u8[>..] = [];
    var d = http::hpack_table(4096);
    var e = http::hpack_table(4096);
    var dead = false;               // the connection's decoder refused a block
    var pending: u8[>..] = [];      // encode: the block's fields, as records
    var have = false;
    fn flush_encode() {
        if !have { return; }
        have = false;
        var enc: u8[>..] = [];
        http::hpack_begin(e, enc);
        http::each_hpack_field(pending) { n, v, s => http::hpack_field(e, enc, n, v, s); };
        out.append("block");
        h(out, enc);
        out.push('\n');
        http::each_hpack_field(pending) { n, v, s =>
            out.append("field");
            h(out, n);
            h(out, v);
            out.append(if s { " 1\n" } else { " 0\n" });
        };
        pending.clear();
    }
    each_split(text, '\n') {
        var p: u8[:][>..] = [];
        each_split(it, ' ') { p.push(it); };
        if p.len > 0 {
            if p[0] == "conn" {
                if mode == "encode" { flush_encode(); }
                let n, ok = parse_int(p[1]);
                d = http::hpack_table(n);
                e = http::hpack_table(n);
                dead = false;
                out.append(it);
                out.push('\n');
            } else if p[0] == "limit" {
                if mode == "encode" {
                    flush_encode();
                    let n, ok = parse_int(p[1]);
                    http::hpack_peer_limit(e, n);
                }
            } else if p[0] == "block" {
                if mode == "decode" {
                    if !dead {
                        out.append(it);
                        out.push('\n');
                        var recs: u8[>..] = [];
                        let r = http::hpack_decode(d, unhex(p[1]), 1 << 40, recs);
                        if r != http::HPACK_OK {
                            out.append("error\n");
                            dead = true;
                        } else {
                            out.append("ok\n");
                            http::each_hpack_field(recs) { n, v, s =>
                                out.append("field");
                                h(out, n);
                                h(out, v);
                                out.append(if s { " 1\n" } else { " 0\n" });
                            };
                        }
                    }
                } else {
                    flush_encode();
                    have = true;
                }
            } else if p[0] == "field" && mode == "encode" {
                let n = unhex(p[1]);
                let v = unhex(p[2]);
                http::hpack_put_record(pending, n, v, p[3] == "1");
            }
        }
        if out.len > (1 << 20) { write_stdout(out); out.clear(); }
    };
    if mode == "encode" { flush_encode(); }
    write_stdout(out);
    flush_stdout();
}

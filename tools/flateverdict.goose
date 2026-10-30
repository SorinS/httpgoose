// flateverdict: decodes each case of a cases file with http.flate, fed in
// the chunk sizes the case gives, for scripts/flate_differential.py. A case
// is "FORMAT CHUNK HEX" a line ("-" for no bytes; FORMAT gzip or deflate, CHUNK the bytes a
// feed); the output a line: "ok SIZE CRC32" (of what decoded), "err N"
// for an error, or "short" when the stream ended unfinished.
//
//	goose tools/flateverdict.goose -- cases.txt

import std;
import os;
import http from "..";
import http.flate;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: flateverdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("flateverdict: cannot read ", a[1]); exit(1); }
    var out: u8[>..] = [];
    each_split(data, '\n') {
        let f = split(trim(it), ' ');
        if f.len == 3 {
            var d = if f[0] == "gzip" { http::gzip_decoder() } else { http::deflate_decoder() };
            let chunk, ok = parse_int(f[1]);
            var bin: u8[>..] = [];
            var i = 0;
            let h = if f[2] == "-" { "" } else { f[2] };
            while i + 1 < h.len { bin.push((hexval(h[i]) * 16 + hexval(h[i + 1])) as! u8); i += 2; }
            var dec: u8[>..] = [];
            var e: i64 = 0;
            var p = 0;
            while p < bin.len && e == 0 {
                let n = if bin.len - p < chunk { bin.len - p } else { chunk };
                e = http::inflate_feed(d, bin[p..p + n], dec);
                p += n;
            }
            if e != 0 { out.append("err "); format(out, e); }
            else if !http::inflate_done(d) { out.append("short"); }
            else {
                out.append("ok ");
                format(out, dec.len);
                out.push(' ');
                format_uint(out, http::crc32(dec), 16, 8, '0');
            }
            out.push('\n');
        }
    };
    write_stdout(out);
    flush_stdout();
}

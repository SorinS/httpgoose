// http.flate: gzip, zlib and raw DEFLATE streams (made with Python's zlib)
// decoded whole and a byte at a time, errors, and CRC-32 and Adler-32.
// scripts/flate_differential.py compares thousands more with zlib.

import std;
import http from "..";
import http.url;
import http.flate;

var failures = 0;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((http::url_hex(s[i]) * 16 + http::url_hex(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn decode(format: u8, s: const u8[:], chunk: i64) -> u8[>..], i64, bool {
    var d = http::new_inflate(format);
    var out: u8[>..] = [];
    var p = 0;
    var e: i64 = 0;
    while p < s.len && e == 0 {
        let n = if s.len - p < chunk { s.len - p } else { chunk };
        e = http::inflate_feed(d, s[p..p + n], out);
        p += n;
    }
    return out, e, http::inflate_done(d);
}

fn case(name: const u8[:], format: u8, hex: const u8[:], want: const u8[:]) {
    let s = unhex(hex);
    for chunk in [1, 3, 1 << 20] {
        let out, e, done = decode(format, s, chunk);
        if e != 0 || !done || out[..] != want {
            print("FAIL ", name, " chunk ", chunk, ": err ", e, " done ", done, " got ", out.len, " bytes");
            failures++;
        }
    }
}

fn bad(name: const u8[:], format: u8, hex: const u8[:], want_err: i64) {
    let s = unhex(hex);
    let out, e, done = decode(format, s, 1);
    if want_err == 0 {
        if e != 0 || done { print("FAIL ", name, ": err ", e, " done ", done); failures++; }
    } else if e != want_err {
        print("FAIL ", name, ": err ", e, ", want ", want_err);
        failures++;
    }
}

// A gzip member whose FEXTRA, FNAME and FCOMMENT are far longer than what
// the decoder keeps of its input (FLATE_PENDING): they are read as they
// come, and FHCRC checks all of them.
fn long_header() {
    var m: u8[>..] = [];
    m.append([0x1f, 0x8b, 8, 4 | 8 | 16 | 2, 0, 0, 0, 0, 0, 3]);
    m.push(0x60);                       // XLEN 60000
    m.push(0xea);
    for k in 60000 { m.push(((k * 13) % 256) as! u8); }
    for k in 10000 { m.push('n'); }
    m.push(0);
    for k in 5000 { m.push('c'); }
    m.push(0);
    let h = http::crc32(m) & 0xffff;
    m.push((h & 0xff) as! u8);
    m.push((h >> 8) as! u8);
    // "hi" as a fixed-Huffman block, and its trailer.
    m.append([0xcb, 0xc8, 0x04, 0x00]);
    let c = http::crc32("hi");
    for k in 4 { m.push(((c >> ((k * 8) as! u32)) & 0xff) as! u8); }
    m.append([2, 0, 0, 0]);
    for chunk in [1, 1000, 1 << 20] {
        let out, e, done = decode(http::FLATE_GZIP, m, chunk);
        if e != 0 || !done || out[..] != "hi" {
            print("FAIL long header fields, chunk ", chunk, ": err ", e, " done ", done, " got '", out, "'");
            failures++;
        }
    }
    // A wrong FHCRC is caught after all that.
    m[10 + 2 + 60000 + 10001 + 5001] ^= 1;     // the first byte of FHCRC
    let out2, e2, done2 = decode(http::FLATE_GZIP, m, 777);
    if e2 != http::FLATE_ERR_CHECK { print("FAIL long header, wrong FHCRC: err ", e2); failures++; }
}

fn main() {
    case("gzip with a name", http::FLATE_GZIP,
         "1f8b080800000000000368656c6c6f2e74787400cb48cdc9c9d75128cf2fca49e10200537424f40d000000", "hello, world\n");
    case("gzip empty", http::FLATE_GZIP, "1f8b080000000000000303000000000000000000", "");
    case("gzip two members", http::FLATE_GZIP,
         "1f8b0800000000000003cbcf4b5500004961ac23040000001f8b08000000000000032b29cf0700668aca1103000000", "one two");
    case("zlib", http::FLATE_ZLIB, "78da4b494dcb492c4955c8cc53f008090950c82c56a8cac94c0200610f07fa", "deflate in HTTP is zlib");
    case("raw deflate", http::FLATE_ZLIB, "2b4a2c5748494dcb492c49d551482c5628cecf4d55284e2d2a4b2d027252f35200",
         "raw deflate, as some servers send");
    var all: u8[>..] = [];
    for r in 2 { for b in 256 { all.push(b as! u8); } }
    case("gzip dynamic", http::FLATE_GZIP, "1f8b08000000000000036360646266616563e7e0e4e2e6e1e5e3171014121611151397909492969195935750545256515553d7d0d4d2d6d1d5d33730343236313533b7b0b4b2b6b1b5b37770747276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c8a8e898d8b4f484c4a4e494d4bcfc8cccacec9cdcb2f282c2a2e292d2bafa8acaaaea9adab6f686c6a6e696d6befe8eceaeee9edeb9f3071d2e42953a74d9f3173d6ec3973e7cd5fb070d1e2254b972d5fb172d5ea356bd7addfb071d3e62d5bb76ddfb173d7ee3d7bf7ed3f70f0d0e123478f1d3f71f2d4e93367cf9dbf70f1d2e52b57af5dbf71f3d6ed3b77efdd7ff0f0d1e3274f9f3d7ff1f2d5eb376fdfbdfff0f1d3e72f5fbf7dfff1f3d7ef3f7ffffd6718e1fe07007635611c00020000", all);
    // A stored block written by hand: BFINAL, BTYPE 00, LEN 5, NLEN.
    case("stored", http::FLATE_ZLIB, "010500faff68656c6c6f", "hello");
    bad("not gzip", http::FLATE_GZIP, "1f8c0800000000000003", http::FLATE_ERR_HEADER);
    bad("bad crc", http::FLATE_GZIP, "1f8b080000000000000303000000000100000000", http::FLATE_ERR_CHECK);
    bad("bad length", http::FLATE_GZIP, "1f8b080000000000000303000000000000000001", http::FLATE_ERR_CHECK);
    bad("bad adler", http::FLATE_ZLIB, "78da4b494dcb492c4955c8cc53f008090950c82c56a8cac94c0200610f07fb", http::FLATE_ERR_CHECK);
    bad("cut short", http::FLATE_GZIP, "1f8b08000000000000030300000000", 0);
    bad("trailing junk", http::FLATE_GZIP, "1f8b0800000000000003030000000000000000006a756e6b", http::FLATE_ERR_TRAILING);
    bad("block type 3", http::FLATE_ZLIB, "0700", http::FLATE_ERR_DATA);
    bad("stored nlen", http::FLATE_ZLIB, "010500fbff68656c6c6f", http::FLATE_ERR_DATA);
    bad("distance too far", http::FLATE_ZLIB, "030200", http::FLATE_ERR_DATA);
    long_header();
    if http::crc32("The quick brown fox jumps over the lazy dog") != 0x414fa339 { print("FAIL crc32"); failures++; }
    if http::adler32_update(1, "Wikipedia") != 0x11e60398 { print("FAIL adler32"); failures++; }
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("flate: all passed");
}

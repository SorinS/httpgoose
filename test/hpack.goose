// http.hpack: RFC 7541 Appendix C's examples (test/vectors/hpack_rfc.txt
// from scripts/gen_hpack_vectors.py): integers (C.1), each field
// representation (C.2), and the request and response series without and
// with Huffman coding (C.3 to C.6), decoded with the tables after each
// blk, and encoded again (the Huffman series to the RFC's own bytes).
// Then the errors a decoder must find, size updates, and list limits.
// scripts/hpack_differential.py checks against Go's hpack package.

import std;
import http from "..";
import http.hpack;
import http.h1;

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

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let d = "0123456789abcdef";
    for c in b { out.push(d[(c >> 4) as i64]); out.push(d[(c & 15) as i64]); }
    return out;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((http::hex_value(s[i]) * 16 + http::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

// The decoded fields as "name: value" lines, "!" before a never-indexed one.
fn lines(recs: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    http::each_hpack_field(recs) { n, v, s =>
        if s { out.push('!'); }
        out.append(n);
        out.append(": ");
        out.append(v);
        out.push('\n');
    };
    return out;
}

// The dynamic table, newest first.
fn table_lines(t: const http::HpackTable&) -> u8[>..] {
    var out: u8[>..] = [];
    for i in 1..t.count + 1 {
        let n, v = http::hpack_entry(t, i);
        out.append(n);
        out.append(": ");
        out.append(v);
        out.push('\n');
    }
    return out;
}

fn integers() {
    // C.1.1 to C.1.3.
    var a: u8[>..] = [];
    http::hpack_put_int(a, 0, 5, 10);
    check("C.1.1", hex(a), "0a");
    var b: u8[>..] = [];
    http::hpack_put_int(b, 0, 5, 1337);
    check("C.1.2", hex(b), "1f9a0a");
    var c: u8[>..] = [];
    http::hpack_put_int(c, 0, 8, 42);
    check("C.1.3", hex(c), "2a");
    let v, end = http::hpack_int(b, 0, 5);
    check_int("C.1.2 read", v, 1337);
    check_int("C.1.2 end", end, 3);
    // Past 2^31, too many continuation bytes, or cut short.
    let v2, e2 = http::hpack_int(unhex("1fffffffff0f"), 0, 5);
    check_int("overflow", e2, -1);
    let v3, e3 = http::hpack_int(unhex("1f80808080808080808000"), 0, 5);
    check_int("63 bits of continuation", e3, -1);
    let v4, e4 = http::hpack_int(unhex("1f9a"), 0, 5);
    check_int("cut short", e4, -1);
    let v5, e5 = http::hpack_int(unhex("1f8180808080808000"), 0, 5);
    check_int("continuation bytes that add nothing (as Go)", v5, 32);
    let v7, e7 = http::hpack_int(unhex("1fe1ffffff07"), 0, 5);
    check_int("2^31 is past the limit", e7, -1);
    var m: u8[>..] = [];
    http::hpack_put_int(m, 0, 7, 0x7fffffff);
    let v6, e6 = http::hpack_int(m, 0, 7);
    check_int("2^31-1", v6, 0x7fffffff);
}

fn rfc_vectors() {
    var text: u8[>..] = [];
    text.append(embed_file("vectors/hpack_rfc.txt"));
    var d = http::hpack_table(4096);
    var e = http::hpack_table(4096);
    var back = http::hpack_table(4096);
    var series_block = 0;
    var tag: u8[>..] = [];
    var blk: u8[>..] = [];
    var want: u8[>..] = [];
    var want_table: u8[>..] = [];
    var want_size: i64 = -1;
    var got_table: u8[>..] = [];
    var got_size: i64 = 0;
    var blocks = 0;
    // A block's fields, as decoded, kept to encode again.
    var recs: u8[>..] = [];
    fn finish_block() {
        if blk.len == 0 { return; }
        recs.clear();
        let r = http::hpack_decode(d, blk, 1 << 20, recs);
        check_int(str(tag, " decode result"), r, http::HPACK_OK);
        check(str(tag, " fields"), lines(recs), want);
        check(str(tag, " table"), table_lines(d), want_table);
        if want_size >= 0 { check_int(str(tag, " size"), d.size, want_size); }
        // Encoded again: the Huffman series as the RFC has them; every one
        // decodes to the same fields.
        var enc: u8[>..] = [];
        http::hpack_begin(e, enc);
        http::each_hpack_field(recs) { n, v, s => http::hpack_field(e, enc, n, v, s); };
        // C.6.2 Huffman-codes ":status: 307" at its plain length (3 bytes);
        // this encoder, as Go's, takes Huffman only when it is shorter.
        series_block++;
        if tag == "C.6" && series_block == 2 {
            check("C.6.2 encoded as Go does", hex(enc), "4803333037c1c0bf");
        } else if tag == "C.4" || tag == "C.6" {
            check(str(tag, " encoded as the RFC"), hex(enc), hex(blk));
        }
        var again: u8[>..] = [];
        check_int(str(tag, " encoding decodes"), http::hpack_decode(back, enc, 1 << 20, again), http::HPACK_OK);
        check(str(tag, " encoding decodes to the fields"), lines(again), lines(recs));
        blocks++;
        blk.clear();
        want.clear();
        want_table.clear();
        want_size = -1;
    }
    each_split(text, '\n') {
        let line = it;
        if line.len > 0 && line[0] != '#' {
            var parts: u8[:][>..] = [];
            each_split(line, '\t') { parts.push(it); };
            if parts[0] == "series" {
                finish_block();
                let lim, ok = parse_int(parts[1]);
                d = http::hpack_table(lim);
                e = http::hpack_table(lim);
                back = http::hpack_table(lim);
                series_block = 0;
                tag.clear();
                tag.append(parts[2]);
            } else if parts[0] == "block" {
                finish_block();
                blk.append(unhex(parts[1]));
            } else if parts[0] == "field" {
                if parts[3] == "1" { want.push('!'); }
                want.append(parts[1]);
                want.append(": ");
                want.append(parts[2]);
                want.push('\n');
            } else if parts[0] == "table" {
                want_table.append(parts[1]);
                want_table.append(": ");
                want_table.append(parts[2]);
                want_table.push('\n');
            } else if parts[0] == "size" {
                let n, ok = parse_int(parts[1]);
                want_size = n;
            }
        }
    };
    finish_block();
    check_int("blocks", blocks, 16);
}

// Encoded fields decode back to themselves, through several blocks.
fn round_trip() {
    var e = http::hpack_table(256);
    var d = http::hpack_table(256);
    for round in 20 {
        var enc: u8[>..] = [];
        var want: u8[>..] = [];
        http::hpack_begin(e, enc);
        for k in 6 {
            var n: u8[>..] = [];
            var v: u8[>..] = [];
            n.append("x-field-");
            format(n, (round * 7 + k) % 9);
            v.append("value ");
            format(v, round * k);
            for j in (round * 13 + k) % 40 { v.push(('a' as i64 + (j % 26)) as! u8); }
            let sensitive = k == 3;
            http::hpack_field(e, enc, n, v, sensitive);
            if sensitive { want.push('!'); }
            want.append(n);
            want.append(": ");
            want.append(v);
            want.push('\n');
        }
        var recs: u8[>..] = [];
        check_int("round trip result", http::hpack_decode(d, enc, 1 << 20, recs), http::HPACK_OK);
        check(str("round trip ", round), lines(recs), want);
        check(str("round trip table ", round), table_lines(d), table_lines(e));
    }
    // Every byte value through Huffman coding.
    var all: u8[>..] = [];
    for k in 256 { all.push(k as! u8); }
    var h: u8[>..] = [];
    http::huffman_encode(h, all);
    check_int("huffman length", h.len, http::huffman_length(all));
    var back: u8[>..] = [];
    if !http::huffman_decode(h, back) { print("FAIL huffman of every byte refused"); failures++; }
    check("huffman of every byte", hex(back), hex(all));
}

fn decode_result(limit: i64, block_hex: const u8[:], max_list: i64) -> i64 {
    var d = http::hpack_table(limit);
    var recs: u8[>..] = [];
    return http::hpack_decode(d, unhex(block_hex), max_list, recs);
}

fn errors() {
    let E = http::HPACK_ERROR;
    check_int("index 0", decode_result(4096, "80", 1 << 20), E);
    check_int("index past the tables", decode_result(4096, "be", 1 << 20), E);
    check_int("literal name index past the tables", decode_result(4096, "7e0161", 1 << 20), E);
    check_int("string longer than the block", decode_result(4096, "400a6162", 1 << 20), E);
    // Huffman strings: one that ends right, and the ways one can be wrong.
    check_int("huffman string ok", huff_case("a", ""), http::HPACK_OK);
    check_int("huffman padding of zeros", huff_case("a", "zeros"), E);
    check_int("huffman padding of 8 bits", huff_case("a", "long"), E);
    check_int("huffman EOS", huff_case("", "eos"), E);
    // Size updates: at most the limit, and only before the block's fields.
    check_int("size update to the limit", decode_result(4096, "3fe11f", 1 << 20), http::HPACK_OK);
    check_int("size update past the limit", decode_result(4096, "3fe21f", 1 << 20), E);
    check_int("size update after a field", decode_result(4096, "8220", 1 << 20), E);
    check_int("two size updates first", decode_result(4096, "203f8101", 1 << 20), http::HPACK_OK);
    // The list limit: §4.1's size of ":method: GET" is 42.
    check_int("list at its limit", decode_result(4096, "82", 42), http::HPACK_OK);
    check_int("list past its limit", decode_result(4096, "8282", 83), http::HPACK_TOO_LARGE);
    // Past the limit, the block is still decoded into the table.
    var t = http::hpack_table(4096);
    var r2: u8[>..] = [];
    let res = http::hpack_decode(t, unhex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"), 10, r2);
    check_int("too large result", res, http::HPACK_TOO_LARGE);
    check_int("too large: nothing out", r2.len, 0);
    check_int("too large: the table kept in step", t.count, 1);
    // Evictions: a 100-byte table takes one 60-byte entry at a time; one
    // larger than the table empties it (§4.4).
    var s = http::hpack_table(100);
    http::hpack_add(s, "aaaaaaaaaaaaaaaaaaaa", "bbbbbbbb");     // 60
    http::hpack_add(s, "cccccccccccccccccccc", "dddddddd");     // 60: the first goes
    check_int("eviction count", s.count, 1);
    check(str("eviction keeps the newest"), table_lines(s), "cccccccccccccccccccc: dddddddd\n");
    http::hpack_add(s, "e", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    check_int("an entry larger than the table empties it", s.count, 0);
    check_int("and the size is 0", s.size, 0);
}

// A literal without indexing, new name "x", the value Huffman coded: the
// code of `s`, then the padding asked for.
fn huff_case(s: const u8[:], how: const u8[:]) -> i64 {
    var acc: u64 = 0;
    var n: i64 = 0;
    var bytes: u8[>..] = [];
    for c in s {
        acc = (acc << (http::HUFF_LEN[c] as u64)) | (http::HUFF_CODE[c] as u64);
        n += http::HUFF_LEN[c] as i64;
    }
    if how == "eos" {
        acc = (acc << 30) | 0x3fffffff;
        n += 30;
    }
    var padn: i64 = (8 - n % 8) % 8;
    var ones = true;
    if how == "zeros" { ones = false; if padn == 0 { padn = 8; } }
    if how == "long" { padn += 8; }
    acc = acc << (padn as! u64);
    if ones { acc = acc | ((1 << (padn as! u64)) - 1); }
    n += padn;
    while n >= 8 { n -= 8; bytes.push(((acc >> (n as! u64)) & 0xff) as! u8); }
    var b: u8[>..] = [];
    b.push(0);
    b.push(1);
    b.push('x');
    http::hpack_put_int(b, 0x80, 7, bytes.len);
    b.append(bytes);
    var d = http::hpack_table(4096);
    var recs: u8[>..] = [];
    return http::hpack_decode(d, b, 1 << 20, recs);
}

fn encoder_sizes() {
    // A peer that allows less: the update is owed and sent first, the
    // smallest then the size now (§4.2).
    var e = http::hpack_table(4096);
    var out: u8[>..] = [];
    http::hpack_field(e, out, "x-a", "1", false);
    check_int("indexed into the table", e.count, 1);
    http::hpack_peer_limit(e, 0);
    http::hpack_peer_limit(e, 1000);
    out.clear();
    http::hpack_begin(e, out);
    check(str("updates owed: 0 then 1000"), hex(out), "203fc907");
    check_int("table emptied by the 0", e.count, 0);
    out.clear();
    http::hpack_begin(e, out);
    check_int("owed once", out.len, 0);
    // A peer allowing more than HPACK_MAX: no update, 4096 used.
    var f = http::hpack_table(4096);
    http::hpack_peer_limit(f, 65536);
    out.clear();
    http::hpack_begin(f, out);
    check_int("no update for a larger limit", out.len, 0);
    check_int("still 4096", f.max_size, 4096);
    // Sensitive fields are never indexed (0001), and not added.
    var g = http::hpack_table(4096);
    out.clear();
    http::hpack_field(g, out, "authorization", "secret", true);
    check(str("never indexed, static name 23"), hex(out[..1]), "1f");
    check_int("not added", g.count, 0);
}

fn main() {
    integers();
    rfc_vectors();
    round_trip();
    errors();
    encoder_sizes();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("hpack: all passed");
}

// http.hpack: HPACK (RFC 7541), the header compression of HTTP/2, without
// I/O: a dynamic table, a decoder of header blocks and an encoder.
//
//   var d = http::hpack_table(4096);              // the limit we advertise
//   var fields: u8[>..] = [];
//   let e = http::hpack_decode(d, block, 65536, fields);   // HPACK_OK, ...
//   http::each_hpack_field(fields) { name, value, sensitive => ... };
//
//   var t = http::hpack_table(4096);              // the peer's limit
//   var out: u8[>..] = [];
//   http::hpack_begin(t, out);                    // size updates owed, if any
//   http::hpack_field(t, out, ":method", "GET", false);
//
// Tables hold at most HPACK_MAX bytes (RFC 7541 §4.1's measure): a
// decoder's limit is what its side advertises (SETTINGS_HEADER_TABLE_SIZE,
// 4096 unless told), and an encoder uses at most that much of what the peer
// allows, saying so with a size update (§6.3) when the peer allows less.

namespace http;

import std;
import hpacktab;

let HPACK_MAX: i64 = 4096;
let HPACK_MAX_ENTRIES: i64 = 128;      // HPACK_MAX / 32

let HPACK_OK: i64 = 0;
let HPACK_ERROR: i64 = 1;              // the block is not HPACK: COMPRESSION_ERROR
let HPACK_TOO_LARGE: i64 = 2;          // the list passes the limit (decoded through, the table kept in step)

// A dynamic table (§2.3.2): entries oldest first, their names and values in
// `data`, each entry's lengths in nlen and vlen.
struct HpackTable {
    limit: i64,                         // the most max_size may be (a decoder's setting; an encoder's peer's, at most HPACK_MAX)
    max_size: i64,                      // §4.2: the table's size now
    size: i64,                          // §4.1: each entry's name and value lengths plus 32
    count: i64,
    used: i64,                          // bytes of data in use
    // An encoder's size updates owed (§4.2): the smallest since the last
    // block, then the size now; -1 for none.
    owed_min: i64,
    nlen: u16[128],
    vlen: u16[128],
    data: u8[4096],
}

fn hpack_table(limit: i64) -> HpackTable {
    let l = if limit < 0 { 0 } else if limit > HPACK_MAX { HPACK_MAX } else { limit };
    HpackTable { limit: l, max_size: l, size: 0, count: 0, used: 0, owed_min: -1, nlen: [0; 128], vlen: [0; 128], data: [0; 4096] }
}

// Where entry k (0: the oldest) starts in data.
fn hpack_offset(t: const HpackTable&, k: i64) -> i64 {
    var at = 0;
    for j in k { at += (t.nlen[j] as i64) + (t.vlen[j] as i64); }
    return at;
}

// Dynamic index i (1: the newest) as its position k from the oldest.
fn hpack_entry(t: const HpackTable&, i: i64) -> const u8[:], const u8[:] {
    let k = t.count - i;
    let at = hpack_offset(t, k);
    let n = t.nlen[k] as i64;
    let v = t.vlen[k] as i64;
    return t.data[at..at + n], t.data[at + n..at + n + v];
}

fn hpack_evict_oldest(t: HpackTable&) {
    let n = (t.nlen[0] as i64) + (t.vlen[0] as i64);
    for j in t.used - n { t.data[j] = t.data[j + n]; }
    t.used -= n;
    t.size -= n + 32;
    for j in t.count - 1 { t.nlen[j] = t.nlen[j + 1]; t.vlen[j] = t.vlen[j + 1]; }
    t.count--;
}

// §4.4: entries go, oldest first, until one of this size fits; one larger
// than the table empties it and is not added.
fn hpack_add(t: HpackTable&, name: const u8[:], value: const u8[:]) {
    let need = name.len + value.len + 32;
    while t.count > 0 && t.size + need > t.max_size { hpack_evict_oldest(t); }
    if need > t.max_size { return; }
    for j in name.len { t.data[t.used + j] = name[j]; }
    for j in value.len { t.data[t.used + name.len + j] = value[j]; }
    t.used += name.len + value.len;
    t.nlen[t.count] = name.len as! u16;
    t.vlen[t.count] = value.len as! u16;
    t.count++;
    t.size += need;
}

fn hpack_resize(t: HpackTable&, n: i64) {
    t.max_size = n;
    while t.size > t.max_size { hpack_evict_oldest(t); }
}

// --- Integers and strings (§5) ---------------------------------------------

// An integer with an n-bit prefix at b[pos] (its other bits are the
// caller's): the value and where it ends; end -1 if it is more than
// 2^31 - 1 or the block ends first. Continuation bytes that add nothing
// are taken (RFC 7541 §5.1 does not forbid them) up to 63 bits of them,
// as Go's decoder takes them.
fn hpack_int(b: const u8[:], pos: i64, n: i64) -> i64, i64 {
    if pos >= b.len { return 0, -1; }
    let mask = (1 << n) - 1;
    var v = (b[pos] as i64) & mask;
    var p = pos + 1;
    if v < mask { return v, p; }
    var shift = 0;
    while true {
        if p >= b.len || shift >= 63 { return 0, -1; }
        let c = (b[p] as i64) & 0x7f;
        let more = (b[p] & 0x80) != 0;
        p++;
        if c != 0 {
            if shift > 28 { return 0, -1; }
            v += c << shift;
            if v > 0x7fffffff { return 0, -1; }
        }
        shift += 7;
        if !more { return v, p; }
    }
    return 0, -1;
}

fn hpack_put_int(out: u8[>..]&, first: u8, n: i64, v: i64) {
    let mask = (1 << n) - 1;
    if v < mask { out.push(first | (v as! u8)); return; }
    out.push(first | (mask as! u8));
    var r = v - mask;
    while r >= 128 { out.push(((r & 0x7f) | 0x80) as! u8); r = r >> 7; }
    out.push(r as! u8);
}

// A string literal at pos, decoded (Huffman or not) onto out: where it ends,
// or -1 if it is malformed.
fn hpack_string(b: const u8[:], pos: i64, out: u8[>..]&) -> i64 {
    if pos >= b.len { return -1; }
    let huff = (b[pos] & 0x80) != 0;
    let n, p = hpack_int(b, pos, 7);
    if p < 0 || n > b.len - p { return -1; }
    if !huff { out.append(b[p..p + n]); return p + n; }
    if !huffman_decode(b[p..p + n], out) { return -1; }
    return p + n;
}

// --- Huffman (§5.2, Appendix B) ----------------------------------------------

// Appends the decoding of `s`: false if it holds EOS, a code that does not
// end, or padding longer than 7 bits or not all ones.
fn huffman_decode(s: const u8[:], out: u8[>..]&) -> bool {
    var code: u32 = 0;
    var len: i64 = 0;
    var ones = true;                    // the bits since the last symbol are all 1
    for byte in s {
        var bit = 7;
        while bit >= 0 {
            let x = ((byte >> (bit as! u8)) & 1) as u32;
            bit--;
            code = (code << 1) | x;
            len++;
            if x == 0 { ones = false; }
            if len > 30 { return false; }
            let cnt = HUFF_COUNT[len] as u32;
            if cnt > 0 && code >= HUFF_FIRST[len] && code - HUFF_FIRST[len] < cnt {
                let sym = HUFF_SYMS[(HUFF_OFFSET[len] as i64) + ((code - HUFF_FIRST[len]) as i64)];
                if sym == 256 { return false; }
                out.push(sym as! u8);
                code = 0;
                len = 0;
                ones = true;
            }
        }
    }
    return len <= 7 && ones;
}

fn huffman_length(s: const u8[:]) -> i64 {
    var bits: i64 = 0;
    for c in s { bits += HUFF_LEN[c] as i64; }
    return (bits + 7) / 8;
}

fn huffman_encode(out: u8[>..]&, s: const u8[:]) {
    var acc: u64 = 0;
    var n: i64 = 0;
    for c in s {
        let l = HUFF_LEN[c] as i64;
        acc = (acc << (l as! u64)) | (HUFF_CODE[c] as u64);
        n += l;
        while n >= 8 {
            n -= 8;
            out.push(((acc >> (n as! u64)) & 0xff) as! u8);
        }
    }
    if n > 0 {
        // Padded with the high bits of EOS: ones.
        let padn = 8 - n;
        out.push((((acc << (padn as! u64)) | ((1 << (padn as! u64)) - 1)) & 0xff) as! u8);
    }
}

// --- Decoding ----------------------------------------------------------------

// Each field goes to `out` as a record: u32 name length, u32 value length,
// u8 1 if it must never be indexed (§6.2.3), the name, the value.
fn hpack_put_record(out: u8[>..]&, name: const u8[:], value: const u8[:], sensitive: bool) {
    for k in 4 { out.push(((name.len >> ((3 - k) * 8)) & 0xff) as! u8); }
    for k in 4 { out.push(((value.len >> ((3 - k) * 8)) & 0xff) as! u8); }
    out.push(if sensitive { 1 } else { 0 });
    out.append(name);
    out.append(value);
}

// F(name, value, sensitive) for each record of hpack_decode's.
fn each_hpack_field<F>(recs: const u8[:]) {
    var p = 0;
    while p + 9 <= recs.len {
        var n: i64 = 0;
        var v: i64 = 0;
        for k in 4 { n = (n << 8) | (recs[p + k] as i64); }
        for k in 4 { v = (v << 8) | (recs[p + 4 + k] as i64); }
        let sensitive = recs[p + 8] == 1;
        let at = p + 9;
        F(recs[at..at + n], recs[at + n..at + n + v], sensitive);
        p = at + n + v;
    }
}

// The name of index i in the static or dynamic table; ok false if there is none.
fn hpack_lookup(t: const HpackTable&, i: i64) -> const u8[:], const u8[:], bool {
    if i >= 1 && i <= 61 { return HPACK_STATIC_NAMES[i - 1], HPACK_STATIC_VALUES[i - 1], true; }
    if i > 61 && i - 61 <= t.count {
        let n, v = hpack_entry(t, i - 61);
        return n, v, true;
    }
    return "", "", false;
}

// Decodes a whole header block (the fragments of HEADERS or PUSH_PROMISE
// and its CONTINUATIONs, joined) into records on `out`. A list larger than
// `max_list` (§4.1's measure, as SETTINGS_MAX_HEADER_LIST_SIZE) is
// HPACK_TOO_LARGE, with nothing more added to out, but the block is still
// decoded to its end to keep the table in step (§2.3.2).
fn hpack_decode(t: HpackTable&, b: const u8[:], max_list: i64, out: u8[>..]&) -> i64 {
    var p = 0;
    var list: i64 = 0;
    var too_large = false;
    var fields_seen = false;
    var name: u8[>..] = [];
    var value: u8[>..] = [];
    while p < b.len {
        let c = b[p];
        if (c & 0x80) != 0 {
            // §6.1: indexed.
            let i, q = hpack_int(b, p, 7);
            if q < 0 || i == 0 { return HPACK_ERROR; }
            let n, v, ok = hpack_lookup(t, i);
            if !ok { return HPACK_ERROR; }
            list += n.len + v.len + 32;
            if list > max_list { too_large = true; }
            if !too_large { hpack_put_record(out, n, v, false); }
            p = q;
            fields_seen = true;
            continue;
        }
        if (c & 0xe0) == 0x20 {
            // §6.3: a size update, before the block's first field only.
            let sz, q = hpack_int(b, p, 5);
            if q < 0 || fields_seen || sz > t.limit { return HPACK_ERROR; }
            hpack_resize(t, sz);
            p = q;
            continue;
        }
        // §6.2: a literal; with incremental indexing (01), without (0000),
        // never indexed (0001).
        let indexing = (c & 0xc0) == 0x40;
        let never = (c & 0xf0) == 0x10;
        let prefix: i64 = if indexing { 6 } else { 4 };
        let i, q = hpack_int(b, p, prefix);
        if q < 0 { return HPACK_ERROR; }
        name.clear();
        value.clear();
        p = q;
        if i == 0 {
            p = hpack_string(b, p, name);
            if p < 0 { return HPACK_ERROR; }
        } else {
            let n, v, ok = hpack_lookup(t, i);
            if !ok { return HPACK_ERROR; }
            name.append(n);
        }
        p = hpack_string(b, p, value);
        if p < 0 { return HPACK_ERROR; }
        list += name.len + value.len + 32;
        if list > max_list { too_large = true; }
        if !too_large { hpack_put_record(out, name, value, never); }
        if indexing { hpack_add(t, name, value); }
        fields_seen = true;
    }
    return if too_large { HPACK_TOO_LARGE } else { HPACK_OK };
}

// --- Encoding ----------------------------------------------------------------

// The peer's SETTINGS_HEADER_TABLE_SIZE for an encoder's table: it uses at
// most HPACK_MAX of it, and a smaller size than now is owed to the peer
// as a size update at the next block.
fn hpack_peer_limit(t: HpackTable&, n: i64) {
    let l = if n < 0 { 0 } else if n > HPACK_MAX { HPACK_MAX } else { n };
    t.limit = l;
    if l != t.max_size {
        if t.owed_min < 0 || l < t.owed_min { t.owed_min = l; }
        hpack_resize(t, l);
    }
}

// Starts a header block: the size updates owed, the smallest one first
// (§4.2).
fn hpack_begin(t: HpackTable&, out: u8[>..]&) {
    if t.owed_min < 0 { return; }
    if t.owed_min < t.max_size { hpack_put_int(out, 0x20, 5, t.owed_min); }
    hpack_put_int(out, 0x20, 5, t.max_size);
    t.owed_min = -1;
}

fn hpack_put_string(out: u8[>..]&, s: const u8[:]) {
    let h = huffman_length(s);
    if h < s.len {
        hpack_put_int(out, 0x80, 7, h);
        huffman_encode(out, s);
    } else {
        hpack_put_int(out, 0, 7, s.len);
        out.append(s);
    }
}

// The index of an entry with this name and value (exact true), or of one
// with this name (exact false), or 0.
fn hpack_search(t: const HpackTable&, name: const u8[:], value: const u8[:]) -> i64, bool {
    var name_at = 0;
    for k in 61 {
        if HPACK_STATIC_NAMES[k] == name {
            if HPACK_STATIC_VALUES[k] == value { return k + 1, true; }
            if name_at == 0 { name_at = k + 1; }
        }
    }
    for i in 1..t.count + 1 {
        let n, v = hpack_entry(t, i);
        if n == name {
            if v == value { return 61 + i, true; }
            if name_at == 0 { name_at = 61 + i; }
        }
    }
    return name_at, false;
}

// A field: indexed if the table has it; else a literal, added to the
// table if it fits and is not sensitive, never indexed if it is (as Go's
// encoder). Names are lowercase (RFC 9113 §8.2.1); the caller lowers them.
fn hpack_field(t: HpackTable&, out: u8[>..]&, name: const u8[:], value: const u8[:], sensitive: bool) {
    let i, exact = hpack_search(t, name, value);
    if exact && !sensitive {
        hpack_put_int(out, 0x80, 7, i);
        return;
    }
    let index = !sensitive && name.len + value.len + 32 <= t.max_size;
    if index { hpack_put_int(out, 0x40, 6, i); }
    else if sensitive { hpack_put_int(out, 0x10, 4, i); }
    else { hpack_put_int(out, 0, 4, i); }
    if i == 0 { hpack_put_string(out, name); }
    hpack_put_string(out, value);
    if index { hpack_add(t, name, value); }
}

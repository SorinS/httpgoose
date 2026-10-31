// http.flate: decompression for the gzip and deflate content codings
// (RFC 9110 §8.4.1): DEFLATE (RFC 1951) inside gzip's members (RFC 1952,
// several in a row as Go's gzip.Reader takes them) or zlib's frame
// (RFC 1950, what "deflate" means in HTTP; a raw DEFLATE stream is taken
// too, as browsers do). The decoder is fed the body as it comes and
// appends what it decodes:
//
//   var d = http::gzip_decoder();
//   let e = http::inflate_feed(d, chunk, out);    // 0, or < 0 for an error
//   // at the body's end: http::inflate_done(d) says whether the stream was whole
//
// Huffman codes are decoded a bit at a time, as zlib's puff.c does: correct
// first. Input that ends inside a symbol (or a block's header) is kept
// until more comes, in a buffer of fixed size: input is taken a slice at a
// time, and a gzip header's optional fields (FEXTRA up to 64 KiB, FNAME
// and FCOMMENT of any length) are read as they come, as zlib reads them,
// so a decoder is of fixed size (some 37 KB) and needs no more.

namespace http;

import std;

let FLATE_GZIP: u8 = 1;
let FLATE_ZLIB: u8 = 2;             // or raw DEFLATE, told apart by the first two bytes
let FLATE_RAW: u8 = 3;

// Errors.
let FLATE_ERR_HEADER: i64 = -1;     // not a gzip or zlib header
let FLATE_ERR_DATA: i64 = -2;       // the DEFLATE data is not valid
let FLATE_ERR_CHECK: i64 = -3;      // a CRC-32, Adler-32 or length that does not match
let FLATE_ERR_TRAILING: i64 = -4;   // bytes after the stream that are not another gzip member

let FS_HEADER: u8 = 0;
let FS_BLOCK: u8 = 1;               // at a block's header
let FS_STORED: u8 = 2;              // copying a stored block
let FS_CODES: u8 = 3;               // decoding a compressed block's symbols
let FS_TRAILER: u8 = 4;
let FS_DONE: u8 = 5;                // a member ended: another may follow (gzip)
let FS_FAILED: u8 = 6;

let MAXBITS: i64 = 15;

// The input kept: past a slice of what comes, the most a decoder can be
// left waiting on is a dynamic block's header (under 600 bytes).
let FLATE_PENDING: i64 = 2048;

// A gzip header's parts, read as they come.
let GH_FIXED: u8 = 0;
let GH_XLEN: u8 = 1;
let GH_EXTRA: u8 = 2;
let GH_NAME: u8 = 3;
let GH_COMMENT: u8 = 4;
let GH_HCRC: u8 = 5;

struct Huffman { count: i16[16], symbol: i16[288] }

struct Inflate {
    format: u8,
    state: u8,
    last: bool,                     // the block being decoded is the last
    stored_left: i64,
    bit: i64,                       // bits of pending[0] already used (0-7)
    lencode: Huffman, distcode: Huffman,
    window: u8[32768], wpos: i64, wfull: bool,
    crc: u32, adler: u32, size: u64,
    members: i64,                   // gzip members ended
    gh: u8,                         // the part of a gzip header being read
    gh_flags: u8,
    gh_left: i64,                   // FEXTRA's bytes still to skip
    gh_crc: u32,                    // CRC-32 of the header so far (for FHCRC)
    pending: u8[..2048],            // input not used yet, from pending[0] bit `bit`
}

fn new_huffman() -> Huffman { Huffman { count: [0; 16], symbol: [0; 288] } }

fn new_inflate(format: u8) -> Inflate {
    Inflate {
        format: format, state: if format == FLATE_RAW { FS_BLOCK } else { FS_HEADER }, last: false, stored_left: 0,
        bit: 0, lencode: new_huffman(), distcode: new_huffman(), window: [0; 32768], wpos: 0, wfull: false,
        crc: 0xffffffff, adler: 1, size: 0, members: 0,
        gh: GH_FIXED, gh_flags: 0, gh_left: 0, gh_crc: 0, pending: [],
    }
}

fn gzip_decoder() -> Inflate { new_inflate(FLATE_GZIP) }
fn deflate_decoder() -> Inflate { new_inflate(FLATE_ZLIB) }

// --- Checks ----------------------------------------------------------------

let CRC_NIBBLE: u32[16] = [
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
];

fn crc32_update(crc: u32, data: const u8[:]) -> u32 {
    var c = crc;
    for b in data {
        c ^= b;
        c = (c >> 4) ^ CRC_NIBBLE[c & 15];
        c = (c >> 4) ^ CRC_NIBBLE[c & 15];
    }
    return c;
}

// CRC-32 (ISO-HDLC, gzip's) of data.
fn crc32(data: const u8[:]) -> u32 { crc32_update(0xffffffff, data) ^ 0xffffffff }

fn adler32_update(a: u32, data: const u8[:]) -> u32 {
    var s1: u64 = a & 0xffff;
    var s2: u64 = a >> 16;
    for b in data {
        s1 = (s1 + b) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return ((s2 << 16) | s1) as! u32;
}

// --- Bits ------------------------------------------------------------------

// A reader over d.pending from the current bit, that can be wound back.
struct Bits { pos: i64, bit: i64, ok: bool }

fn bits_start(d: const Inflate&) -> Bits { Bits { pos: 0, bit: d.bit, ok: true } }

// n bits (LSB first), or 0 with b.ok false when the input runs out.
fn need(d: const Inflate&, b: Bits&, n: i64) -> i64 {
    var v: i64 = 0;
    for k in n {
        if b.pos >= d.pending.len { b.ok = false; return 0; }
        v |= (((d.pending[b.pos] >> b.bit) & 1) as i64) << k;
        b.bit++;
        if b.bit == 8 { b.bit = 0; b.pos++; }
    }
    return v;
}

// The input up to the reader's position is used.
fn commit(d: Inflate&, b: const Bits&) {
    let n = b.pos;
    if n > 0 {
        let rest = d.pending.len - n;
        for k in rest { d.pending[k] = d.pending[n + k]; }
        d.pending.resize(rest);
    }
    d.bit = b.bit;
}

// A symbol of a Huffman code, or -1 (b.ok false: more input; true: not a code).
fn decode_symbol(d: const Inflate&, b: Bits&, h: const Huffman&) -> i64 {
    var code: i64 = 0;
    var first: i64 = 0;
    var index: i64 = 0;
    for len in 1..MAXBITS + 1 {
        code |= need(d, b, 1);
        if !b.ok { return -1; }
        let count = h.count[len] as i64;
        if code - count < first { return h.symbol[index + (code - first)] as i64; }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

// Builds a canonical Huffman code from code lengths: 0 for a complete
// code, > 0 for an incomplete one, < 0 for an over-subscribed one.
fn construct(h: Huffman&, lengths: const i16[:]) -> i64 {
    for k in 16 { h.count[k] = 0; }
    for l in lengths { h.count[l]++; }
    if h.count[0] as i64 == lengths.len { return 0; }
    var left: i64 = 1;
    for len in 1..MAXBITS + 1 {
        left <<= 1;
        left -= h.count[len] as i64;
        if left < 0 { return left; }
    }
    var offs: i64[16] = [0; 16];
    for len in 1..MAXBITS { offs[len + 1] = offs[len] + h.count[len] as i64; }
    for sym in lengths.len {
        let l = lengths[sym];
        if l != 0 {
            h.symbol[offs[l]] = sym as! i16;
            offs[l]++;
        }
    }
    return left;
}

// --- Output ----------------------------------------------------------------

fn emit_byte(d: Inflate&, out: u8[>..]&, c: u8) {
    out.push(c);
    d.window[d.wpos] = c;
    d.wpos++;
    if d.wpos == 32768 { d.wpos = 0; d.wfull = true; }
}

// Checks of what this block decoded, out[from..].
fn account(d: Inflate&, out: const u8[:]) {
    if d.format == FLATE_GZIP { d.crc = crc32_update(d.crc, out); }
    else if d.format == FLATE_ZLIB { d.adler = adler32_update(d.adler, out); }
    d.size += out.len as! u64;
}

let LBASE: i16[29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
let LEXT: i16[29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
let DBASE: i32[30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
                      4097, 6145, 8193, 12289, 16385, 24577];
let DEXT: i16[30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
let CL_ORDER: i64[19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// --- Blocks ----------------------------------------------------------------

// A block's header: 1 when its state is set, 0 for more input, < 0 for an error.
fn block_header(d: Inflate&) -> i64 {
    var b = bits_start(d);
    let last = need(d, b, 1);
    let typ = need(d, b, 2);
    if !b.ok { return 0; }
    d.last = last == 1;
    if typ == 0 {
        // Stored: to a byte boundary, then LEN and NLEN.
        if b.bit != 0 { b.bit = 0; b.pos++; }
        if b.pos + 4 > d.pending.len { return 0; }
        let len = d.pending[b.pos] as i64 | (d.pending[b.pos + 1] as i64) << 8;
        let nlen = d.pending[b.pos + 2] as i64 | (d.pending[b.pos + 3] as i64) << 8;
        if len != (nlen ^ 0xffff) { return FLATE_ERR_DATA; }
        b.pos += 4;
        commit(d, b);
        d.stored_left = len;
        d.state = FS_STORED;
        return 1;
    }
    if typ == 1 {
        var lengths: i16[288] = [0; 288];
        for k in 144 { lengths[k] = 8; }
        for k in 144..256 { lengths[k] = 9; }
        for k in 256..280 { lengths[k] = 7; }
        for k in 280..288 { lengths[k] = 8; }
        construct(d.lencode, lengths);
        var dl: i16[30] = [5; 30];
        construct(d.distcode, dl);
        commit(d, b);
        d.state = FS_CODES;
        return 1;
    }
    if typ == 2 {
        let nlen = need(d, b, 5) + 257;
        let ndist = need(d, b, 5) + 1;
        let ncode = need(d, b, 4) + 4;
        if !b.ok { return 0; }
        if nlen > 286 || ndist > 30 { return FLATE_ERR_DATA; }
        var lengths: i16[320] = [0; 320];
        for k in ncode {
            lengths[CL_ORDER[k]] = need(d, b, 3) as! i16;
            if !b.ok { return 0; }
        }
        var lencode = new_huffman();
        if construct(lencode, lengths[..19]) != 0 { return FLATE_ERR_DATA; }
        for k in 19 { lengths[k] = 0; }
        var index = 0;
        while index < nlen + ndist {
            let sym = decode_symbol(d, b, lencode);
            if !b.ok { return 0; }
            if sym < 0 { return FLATE_ERR_DATA; }
            if sym < 16 {
                lengths[index] = sym as! i16;
                index++;
            } else {
                var len: i16 = 0;
                var rep: i64 = 0;
                if sym == 16 {
                    if index == 0 { return FLATE_ERR_DATA; }
                    len = lengths[index - 1];
                    rep = 3 + need(d, b, 2);
                } else if sym == 17 {
                    rep = 3 + need(d, b, 3);
                } else {
                    rep = 11 + need(d, b, 7);
                }
                if !b.ok { return 0; }
                if index + rep > nlen + ndist { return FLATE_ERR_DATA; }
                for k in rep { lengths[index] = len; index++; }
            }
        }
        if lengths[256] == 0 { return FLATE_ERR_DATA; }      // no end-of-block code
        // An incomplete code is allowed only for a single length of one bit.
        let e1 = construct(d.lencode, lengths[..nlen]);
        if e1 < 0 || (e1 > 0 && nlen - (d.lencode.count[0] as i64) != 1) { return FLATE_ERR_DATA; }
        let e2 = construct(d.distcode, lengths[nlen..nlen + ndist]);
        if e2 < 0 || (e2 > 0 && ndist - (d.distcode.count[0] as i64) != 1) { return FLATE_ERR_DATA; }
        commit(d, b);
        d.state = FS_CODES;
        return 1;
    }
    return FLATE_ERR_DATA;
}

// A compressed block's symbols: 1 at its end, 0 for more input, < 0 for an
// error.
fn codes(d: Inflate&, out: u8[>..]&) -> i64 {
    while true {
        var b = bits_start(d);
        let sym = decode_symbol(d, b, d.lencode);
        if !b.ok { return 0; }
        if sym < 0 { return FLATE_ERR_DATA; }
        if sym < 256 {
            commit(d, b);
            emit_byte(d, out, sym as! u8);
            continue;
        }
        if sym == 256 {
            commit(d, b);
            return 1;
        }
        let s = sym - 257;
        if s >= 29 { return FLATE_ERR_DATA; }
        let len = LBASE[s] as i64 + need(d, b, LEXT[s] as i64);
        let ds = decode_symbol(d, b, d.distcode);
        if !b.ok { return 0; }
        if ds < 0 || ds >= 30 { return FLATE_ERR_DATA; }
        let dist = DBASE[ds] as i64 + need(d, b, DEXT[ds] as i64);
        if !b.ok { return 0; }
        let have = if d.wfull { 32768 } else { d.wpos };
        if dist > have { return FLATE_ERR_DATA; }
        commit(d, b);
        for k in len {
            var at = d.wpos - dist;
            if at < 0 { at += 32768; }
            emit_byte(d, out, d.window[at]);
        }
    }
    return 0;
}

// --- Frames ----------------------------------------------------------------

// gzip's member header (RFC 1952 §2.3): 1 when read, 0 for more input.
fn gzip_header(d: Inflate&) -> i64 {
    while true {
        let m = d.pending[..];
        var used: i64 = 0;
        let starting = d.gh == GH_FIXED;
        if d.gh == GH_FIXED {
            if m.len < 10 { return 0; }
            if m[0] != 0x1f || m[1] != 0x8b || m[2] != 8 { return FLATE_ERR_HEADER; }
            if (m[3] & 0xe0) != 0 { return FLATE_ERR_HEADER; }
            d.gh_flags = m[3];
            used = 10;
            d.gh = GH_XLEN;
        } else if d.gh == GH_XLEN {
            if (d.gh_flags & 4) == 0 { d.gh = GH_NAME; continue; }      // FEXTRA
            if m.len < 2 { return 0; }
            d.gh_left = m[0] as i64 | (m[1] as i64) << 8;
            used = 2;
            d.gh = GH_EXTRA;
        } else if d.gh == GH_EXTRA {
            if d.gh_left > 0 && m.len == 0 { return 0; }
            used = if m.len < d.gh_left { m.len } else { d.gh_left };
            d.gh_left -= used;
            if d.gh_left == 0 { d.gh = GH_NAME; }
        } else if d.gh == GH_NAME || d.gh == GH_COMMENT {
            let flag: u8 = if d.gh == GH_NAME { 8 } else { 16 };              // FNAME, FCOMMENT
            if (d.gh_flags & flag) == 0 {
                d.gh = if d.gh == GH_NAME { GH_COMMENT } else { GH_HCRC };
                continue;
            }
            if m.len == 0 { return 0; }
            let z = position(m, 0);
            if z < 0 {
                used = m.len;
            } else {
                used = z + 1;
                d.gh = if d.gh == GH_NAME { GH_COMMENT } else { GH_HCRC };
            }
        } else {
            if (d.gh_flags & 2) != 0 {                                      // FHCRC
                if m.len < 2 { return 0; }
                let c = (d.gh_crc ^ 0xffffffff) & 0xffff;
                if c != (m[0] as u32 | (m[1] as u32) << 8) { return FLATE_ERR_CHECK; }
                var b2 = Bits { pos: 2, bit: 0, ok: true };
                commit(d, b2);
            }
            d.gh = GH_FIXED;
            d.crc = 0xffffffff;
            d.size = 0;
            d.wpos = 0;
            d.wfull = false;
            return 1;
        }
        if used > 0 {
            d.gh_crc = crc32_update(if starting { 0xffffffff } else { d.gh_crc }, m[..used]);
            var b = Bits { pos: used, bit: 0, ok: true };
            commit(d, b);
        }
    }
    return 0;
}

// zlib's header (RFC 1950 §2.2), or none for raw DEFLATE: 1 when read.
fn zlib_header(d: Inflate&) -> i64 {
    let m = d.pending[..];
    if m.len < 2 { return 0; }
    let cmf = m[0] as i64;
    let flg = m[1] as i64;
    if (cmf & 15) == 8 && (cmf >> 4) <= 7 && (cmf * 256 + flg) % 31 == 0 {
        if (flg & 0x20) != 0 { return FLATE_ERR_HEADER; }   // a preset dictionary
        var b = Bits { pos: 2, bit: 0, ok: true };
        commit(d, b);
        return 1;
    }
    d.format = FLATE_RAW;
    return 1;
}

fn get_le32(m: const u8[:], p: i64) -> u32 {
    return m[p] as u32 | (m[p + 1] as u32) << 8 | (m[p + 2] as u32) << 16 | (m[p + 3] as u32) << 24;
}

// The trailer: gzip's CRC-32 and ISIZE, zlib's Adler-32, none for raw.
fn trailer(d: Inflate&) -> i64 {
    if d.bit != 0 { var b = Bits { pos: 1, bit: 0, ok: true }; commit(d, b); }
    if d.format == FLATE_RAW { return 1; }
    let m = d.pending[..];
    if d.format == FLATE_GZIP {
        if m.len < 8 { return 0; }
        if get_le32(m, 0) != (d.crc ^ 0xffffffff) || get_le32(m, 4) != (d.size & 0xffffffff) as! u32 { return FLATE_ERR_CHECK; }
        var b = Bits { pos: 8, bit: 0, ok: true };
        commit(d, b);
        return 1;
    }
    if m.len < 4 { return 0; }
    let want = (m[0] as u32) << 24 | (m[1] as u32) << 16 | (m[2] as u32) << 8 | m[3] as u32;
    if want != d.adler { return FLATE_ERR_CHECK; }
    var b = Bits { pos: 4, bit: 0, ok: true };
    commit(d, b);
    return 1;
}

// Decodes what of `input` it can, appending to `out`: 0, or an error
// (< 0, after which the decoder takes nothing more).
fn inflate_feed(d: Inflate&, input: const u8[:], out: u8[>..]&) -> i64 {
    if d.state == FS_FAILED { return FLATE_ERR_DATA; }
    var at = 0;
    while true {
        let room = FLATE_PENDING - d.pending.len;
        let n = if input.len - at < room { input.len - at } else { room };
        d.pending.append(input[at..at + n]);
        at += n;
        let r = inflate_run(d, out);
        if r < 0 { return r; }
        if at >= input.len { return 0; }
        // No room, and nothing could be decoded from a full buffer.
        if d.pending.len >= FLATE_PENDING { d.state = FS_FAILED; return FLATE_ERR_DATA; }
    }
    return 0;
}

// Decodes what d.pending holds: 0 when it needs more, or an error.
fn inflate_run(d: Inflate&, out: u8[>..]&) -> i64 {
    while true {
        var r: i64 = 0;
        if d.state == FS_HEADER {
            r = if d.format == FLATE_GZIP { gzip_header(d) } else { zlib_header(d) };
            if r == 1 { d.state = FS_BLOCK; }
        } else if d.state == FS_BLOCK {
            r = block_header(d);
        } else if d.state == FS_STORED {
            let n = if d.pending.len < d.stored_left { d.pending.len } else { d.stored_left };
            let from = out.len;
            for k in n { emit_byte(d, out, d.pending[k]); }
            account(d, out[from..]);
            var b = Bits { pos: n, bit: 0, ok: true };
            commit(d, b);
            d.stored_left -= n;
            r = if d.stored_left == 0 { 1 } else { 0 };
            if r == 1 { d.state = if d.last { FS_TRAILER } else { FS_BLOCK }; }
        } else if d.state == FS_CODES {
            let from = out.len;
            r = codes(d, out);
            account(d, out[from..]);
            if r == 1 { d.state = if d.last { FS_TRAILER } else { FS_BLOCK }; }
        } else if d.state == FS_TRAILER {
            r = trailer(d);
            if r == 1 { d.state = FS_DONE; d.members++; }
        } else if d.state == FS_DONE {
            if d.pending.len == 0 { return 0; }
            // gzip: another member may follow; anything else is an error.
            if d.format != FLATE_GZIP { d.state = FS_FAILED; return FLATE_ERR_TRAILING; }
            if d.pending[0] != 0x1f { d.state = FS_FAILED; return FLATE_ERR_TRAILING; }
            d.state = FS_HEADER;
            r = 1;
        }
        if r < 0 { d.state = FS_FAILED; return r; }
        if r == 0 { return 0; }
    }
    return 0;
}

// Whether the stream ended whole: at least one member (or zlib stream)
// with its trailer, and nothing left over.
fn inflate_done(d: const Inflate&) -> bool { d.state == FS_DONE && d.pending.len == 0 }

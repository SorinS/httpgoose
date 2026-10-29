// http.h1: HTTP/1.1's message syntax (RFC 9112): parsing request and
// response heads, deciding how long a body is (§6.3), decoding chunked
// bodies (§7.1) and writing messages.
//
// The parser is strict where leniency lets two parsers read one byte stream
// as different messages (request smuggling): lines end with CRLF only (a bare
// LF or CR is an error), no whitespace may come between a field name and
// its colon, a line folded onto the one before (obs-fold) is refused, a
// Content-Length must be digits (and a repeated one the same number), a
// Transfer-Encoding needs HTTP/1.1 and chunked as its final coding, and a
// message may not have both. Errors come back as the negative of the status
// to answer with: -400, -414, -431, -501 or -505.

namespace http;

import std;
import http;

struct Limits {
    max_head: i64,          // bytes of a head, start line and fields
    max_line: i64,          // bytes of a request line (414 past it)
    max_fields: i64,        // field lines in a head or a trailer
    max_chunk_ext: i64,     // bytes of extensions on one chunk-size line
    max_trailer: i64,       // bytes of a trailer section
}

fn default_limits() -> Limits {
    Limits { max_head: 65536, max_line: 8192, max_fields: 128, max_chunk_ext: 4096, max_trailer: 16384 }
}

// Results besides the lengths: more bytes are needed, or an error.
let NEED_MORE: i64 = 0;
let ERR_BAD_REQUEST: i64 = -400;
let ERR_URI_TOO_LONG: i64 = -414;
let ERR_FIELDS_TOO_LARGE: i64 = -431;
let ERR_NOT_IMPLEMENTED: i64 = -501;
let ERR_BAD_GATEWAY: i64 = -502;           // a response this client cannot read
let ERR_VERSION: i64 = -505;

// --- Lines -----------------------------------------------------------------

// Where the line from `pos` ends: the index of its CR, -1 if no CRLF has
// come yet, -2 if a bare LF or a CR not followed by LF comes first.
fn line_end(m: const u8[:], pos: i64) -> i64 {
    var i = pos;
    while i < m.len {
        let c = m[i];
        if c == '\n' { return -2; }
        if c == '\r' {
            if i + 1 == m.len { return -1; }
            if m[i + 1] == '\n' { return i; }
            return -2;
        }
        i++;
    }
    return -1;
}

// A field line, m[pos..end] without its CRLF: a token, a colon right after
// it, and a value of field-vchars, spaces and tabs, its leading and
// trailing whitespace dropped (RFC 9112 §5).
fn field_line(m: const u8[:], pos: i64, end: i64) -> Field, bool {
    var f = Field { name: empty_span(), value: empty_span() };
    var i = pos;
    while i < end && is_tchar(m[i]) { i++; }
    if i == pos || i == end || m[i] != ':' { return f, false; }
    f.name = span(pos, i);
    i++;
    while i < end && is_ows(m[i]) { i++; }
    var e = end;
    while e > i && is_ows(m[e - 1]) { e--; }
    for k in i..e {
        let c = m[k];
        if !is_field_vchar(c) && !is_ows(c) { return f, false; }
    }
    f.value = span(i, e);
    return f, true;
}

// The field lines from `pos` up to and including the empty line: the
// index after it, NEED_MORE, or an error.
fn parse_fields(m: const u8[:], pos: i64, h: Head&, lim: const Limits&) -> i64 {
    var p = pos;
    loop {
        if p > lim.max_head { return ERR_FIELDS_TOO_LARGE; }
        if p < m.len && is_ows(m[p]) { return ERR_BAD_REQUEST; }      // obs-fold
        let e = line_end(m, p);
        if e == -2 { return ERR_BAD_REQUEST; }
        if e == -1 { return if m.len > lim.max_head { ERR_FIELDS_TOO_LARGE } else { NEED_MORE }; }
        if e + 2 > lim.max_head { return ERR_FIELDS_TOO_LARGE; }
        if e == p { return e + 2; }
        let f, ok = field_line(m, p, e);
        if !ok { return ERR_BAD_REQUEST; }
        if h.fields.len >= lim.max_fields { return ERR_FIELDS_TOO_LARGE; }
        h.fields.push(f);
        p = e + 2;
    }
}

// "HTTP/" DIGIT "." DIGIT at m[pos..pos + 8].
fn parse_version(m: const u8[:], pos: i64, h: Head&) -> bool {
    if pos + 8 > m.len || m[pos..pos + 5] != "HTTP/" || m[pos + 6] != '.' { return false; }
    let a = m[pos + 5];
    let b = m[pos + 7];
    if a < '0' || a > '9' || b < '0' || b > '9' { return false; }
    h.major = a - '0';
    h.minor = b - '0';
    return true;
}

// --- Requests --------------------------------------------------------------

// A request head at the start of `m`: request-line = method SP
// request-target SP HTTP-version CRLF (§3), then the fields. Returns the
// head and its length in bytes (h.len), NEED_MORE, or an error. Up to four
// empty lines before the request line are skipped (§2.2).
fn parse_request(m: const u8[:], lim: const Limits&) -> Head, i64 {
    var h = new_head(KIND_REQUEST);
    var p = 0;
    for k in 4 {
        if p + 1 < m.len && m[p] == '\r' && m[p + 1] == '\n' { p += 2; }
    }
    if p + 1 < m.len && m[p] == '\r' && m[p + 1] == '\n' { return h, ERR_BAD_REQUEST; }
    let e = line_end(m, p);
    if e == -2 { return h, ERR_BAD_REQUEST; }
    if e == -1 {
        if m.len - p > lim.max_line { return h, ERR_URI_TOO_LONG; }
        return h, NEED_MORE;
    }
    if e - p > lim.max_line { return h, ERR_URI_TOO_LONG; }
    // method SP
    var i = p;
    while i < e && is_tchar(m[i]) { i++; }
    if i == p || i == e || m[i] != ' ' { return h, ERR_BAD_REQUEST; }
    h.method = span(p, i);
    i++;
    // request-target SP: visible ASCII (RFC 3986's characters are a subset)
    let t = i;
    while i < e && m[i] >= 0x21 && m[i] <= 0x7e { i++; }
    if i == t || i == e || m[i] != ' ' { return h, ERR_BAD_REQUEST; }
    h.target = span(t, i);
    i++;
    if e - i != 8 || !parse_version(m, i, h) { return h, ERR_BAD_REQUEST; }
    if h.major != 1 { return h, ERR_VERSION; }
    let n = parse_fields(m, e + 2, h, lim);
    if n <= 0 { return h, n; }
    h.len = n;
    return h, n;
}

// The forms of a request-target (§3.2), checked against the method:
// origin-form "/..." for any method but CONNECT, absolute-form for any
// but CONNECT, authority-form host:port for CONNECT only, and "*" for
// OPTIONS only.
let TARGET_ORIGIN: u8 = 1;
let TARGET_ABSOLUTE: u8 = 2;
let TARGET_AUTHORITY: u8 = 3;
let TARGET_ASTERISK: u8 = 4;

fn target_form(m: const u8[:], h: const Head&) -> u8 {
    let t = m[h.target.pos..h.target.end];
    let method = m[h.method.pos..h.method.end];
    if method == "CONNECT" {
        // host ":" port, no scheme, path, userinfo or query
        let c = rfind(t, ":");
        if c <= 0 || c == t.len - 1 { return 0; }
        for k in c + 1..t.len { if t[k] < '0' || t[k] > '9' { return 0; } }
        for k in c { if t[k] == '/' || t[k] == '@' || t[k] == '?' || t[k] == '#' { return 0; } }
        return TARGET_AUTHORITY;
    }
    if t == "*" { return if method == "OPTIONS" { TARGET_ASTERISK } else { 0 }; }
    if t[0] == '/' { return TARGET_ORIGIN; }
    let s = find(t, "://");
    if s > 0 {
        for k in s {
            let c = t[k];
            let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (k > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'));
            if !ok { return 0; }
        }
        return TARGET_ABSOLUTE;
    }
    return 0;
}

// A request's checks past its syntax: a target of a form its method may
// have, and for HTTP/1.1 exactly one Host (§3.2; RFC 9110 §7.2), whose
// value is a valid authority's characters. Returns 0 or an error.
fn check_request(m: const u8[:], h: const Head&) -> i64 {
    if target_form(m, h) == 0 { return ERR_BAD_REQUEST; }
    let hosts = count(m, h, "host");
    if hosts > 1 || (hosts == 0 && h.minor >= 1) { return ERR_BAD_REQUEST; }
    if hosts == 1 {
        let v, found = get(m, h, "host");
        for k in v.pos..v.end {
            let c = m[k];
            let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '-' || c == '.' || c == '_' || c == '~' || c == ':' || c == '[' || c == ']' ||
                     c == '%' || c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
                     c == '*' || c == '+' || c == ',' || c == ';' || c == '=';
            if !ok { return ERR_BAD_REQUEST; }
        }
    }
    return 0;
}

// --- Responses -------------------------------------------------------------

// A response head: status-line = HTTP-version SP status-code SP
// [reason-phrase] CRLF (§4), then the fields. A status line without the
// space and reason is taken too, as the reason is to be ignored anyway.
fn parse_response(m: const u8[:], lim: const Limits&) -> Head, i64 {
    var h = new_head(KIND_RESPONSE);
    let e = line_end(m, 0);
    if e == -2 { return h, ERR_BAD_GATEWAY; }
    if e == -1 { return h, if m.len > lim.max_head { ERR_BAD_GATEWAY } else { NEED_MORE }; }
    if e < 12 || !parse_version(m, 0, h) || h.major != 1 || m[8] != ' ' { return h, ERR_BAD_GATEWAY; }
    var status = 0;
    for k in 9..12 {
        let c = m[k];
        if c < '0' || c > '9' { return h, ERR_BAD_GATEWAY; }
        status = status * 10 + (c - '0');
    }
    if status < 100 { return h, ERR_BAD_GATEWAY; }
    h.status = status;
    if e > 12 {
        if m[12] != ' ' { return h, ERR_BAD_GATEWAY; }
        for k in 13..e {
            let c = m[k];
            if !is_field_vchar(c) && !is_ows(c) { return h, ERR_BAD_GATEWAY; }
        }
        h.reason = span(13, e);
    } else {
        h.reason = span(e, e);
    }
    let n = parse_fields(m, e + 2, h, lim);
    if n < 0 { return h, ERR_BAD_GATEWAY; }
    if n == 0 { return h, NEED_MORE; }
    h.len = n;
    return h, n;
}

// --- Framing (§6.3) --------------------------------------------------------

let BODY_NONE: u8 = 0;          // no body (or an empty one)
let BODY_LENGTH: u8 = 1;        // Content-Length bytes
let BODY_CHUNKED: u8 = 2;       // the chunked coding
let BODY_CLOSE: u8 = 3;         // a response's, to the end of the connection
let BODY_TUNNEL: u8 = 4;        // after a 2xx to CONNECT, the connection is a tunnel

struct Framing { kind: u8, length: i64 }

// Content-Length (RFC 9110 §8.6): 1*DIGIT, and in each line the same
// text. -1 if invalid. §8.6 lets a recipient take a list of one number
// ("5, 5") or lines of the same number written differently ("5" and
// "05"), or refuse them; they are refused, as Go does, so that no
// parser in front of this one can have read another length.
fn content_length(m: const u8[:], h: const Head&) -> i64 {
    var n: i64 = -1;
    var first = empty_span();
    for f in h.fields {
        if !eq_fold(m[f.name.pos..f.name.end], "content-length") { continue; }
        let s = m[f.value.pos..f.value.end];
        if n >= 0 {
            if s != m[first.pos..first.end] { return -1; }
            continue;
        }
        // Any number of leading zeros, then at most 18 digits, which an i64
        // holds.
        if s.len == 0 { return -1; }
        var v: i64 = 0;
        var digits = 0;
        for c in s {
            if c < '0' || c > '9' { return -1; }
            if digits > 0 || c != '0' { digits++; }
            if digits > 18 { return -1; }
            v = v * 10 + (c - '0');
        }
        n = v;
        first = f.value;
    }
    return n;
}

// Transfer-Encoding's codings in all its lines (§6.1): 1 if they are
// chunked alone, 2 if chunked is final after others (which this package
// does not decode), 3 if chunked is not final, 0 if invalid (a malformed
// coding, or chunked twice). An empty list element is invalid too. RFC
// 9110 §5.6.1.2 has recipients ignore empty elements, but in this field
// one would let "chunked," mean chunked here and no known coding to a
// parser in front of this one, which then sees the body as the next
// request (Go refuses it as well).
fn transfer_codings(m: const u8[:], h: const Head&) -> u8 {
    var chunked = 0;
    var total = 0;
    var last_chunked = false;
    var bad = false;
    for f in h.fields {
        if !eq_fold(m[f.name.pos..f.name.end], "transfer-encoding") { continue; }
        each_split(m[f.value.pos..f.value.end], ',') {
            let s = trim_ows(it);
            if s.len == 0 { bad = true; }
            else {
                // a coding with parameters: the token before ';'
                let semi = position(s, ';');
                let name = trim_ows(if semi >= 0 { s[..semi] } else { s });
                if !is_token(name) { bad = true; }
                total++;
                last_chunked = eq_fold(name, "chunked");
                if last_chunked {
                    chunked++;
                    if semi >= 0 { bad = true; }       // chunked takes no parameters
                }
            }
        };
    }
    if bad || total == 0 || chunked > 1 { return 0; }
    if !last_chunked { return 3; }
    return if total == 1 { 1 } else { 2 };
}

// How a request's body is framed, or an error. A Transfer-Encoding in an
// HTTP/1.0 request, or beside a Content-Length, is faulty framing (§6.1,
// §6.3) and is refused rather than resolved, as a proxy before this server
// may have resolved it the other way.
fn request_framing(m: const u8[:], h: const Head&) -> Framing, i64 {
    var fr = Framing { kind: BODY_NONE, length: 0 };
    let te = count(m, h, "transfer-encoding") > 0;
    let cl = count(m, h, "content-length") > 0;
    if te {
        if h.minor == 0 || cl { return fr, ERR_BAD_REQUEST; }
        let t = transfer_codings(m, h);
        if t == 2 { return fr, ERR_NOT_IMPLEMENTED; }
        if t != 1 { return fr, ERR_BAD_REQUEST; }
        fr.kind = BODY_CHUNKED;
        return fr, 0;
    }
    if cl {
        let n = content_length(m, h);
        if n < 0 { return fr, ERR_BAD_REQUEST; }
        fr.kind = if n > 0 { BODY_LENGTH } else { BODY_NONE };
        fr.length = n;
    }
    return fr, 0;
}

// How a response's body is framed, given the request it answers (§6.3):
// none after HEAD and for 1xx, 204 and 304; a tunnel after a 2xx to
// CONNECT; then Transfer-Encoding, Content-Length, or the rest of the
// connection.
fn response_framing(m: const u8[:], h: const Head&, head_request: bool, connect_request: bool) -> Framing, i64 {
    var fr = Framing { kind: BODY_NONE, length: 0 };
    if head_request || h.status < 200 || h.status == 204 || h.status == 304 { return fr, 0; }
    if connect_request && h.status < 300 { fr.kind = BODY_TUNNEL; return fr, 0; }
    let te = count(m, h, "transfer-encoding") > 0;
    let cl = count(m, h, "content-length") > 0;
    if te {
        if h.minor == 0 || cl { return fr, ERR_BAD_GATEWAY; }
        let t = transfer_codings(m, h);
        if t == 1 { fr.kind = BODY_CHUNKED; return fr, 0; }
        if t == 3 { fr.kind = BODY_CLOSE; return fr, 0; }
        return fr, ERR_BAD_GATEWAY;
    }
    if cl {
        let n = content_length(m, h);
        if n < 0 { return fr, ERR_BAD_GATEWAY; }
        fr.kind = if n > 0 { BODY_LENGTH } else { BODY_NONE };
        fr.length = n;
        return fr, 0;
    }
    fr.kind = BODY_CLOSE;
    return fr, 0;
}

// Whether the connection stays open after this message (§9.3): not if
// either side said Connection: close, and for HTTP/1.0 only if it said
// keep-alive.
fn keep_alive(m: const u8[:], h: const Head&) -> bool {
    if has_token(m, h, "connection", "close") { return false; }
    if h.minor == 0 { return has_token(m, h, "connection", "keep-alive"); }
    return true;
}

// --- The chunked coding (§7.1) --------------------------------------------

// chunked-body = *chunk last-chunk trailer-section CRLF
// chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
// chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
let CK_SIZE: u8 = 0;
let CK_EXT: u8 = 1;             // after the size: OWS, ';' or CR
let CK_EXT_NAME0: u8 = 2;       // after ';'
let CK_EXT_NAME: u8 = 3;
let CK_EXT_AFTER_NAME: u8 = 4;  // OWS after a name
let CK_EXT_VAL0: u8 = 5;        // after '='
let CK_EXT_VAL: u8 = 6;         // a token value
let CK_EXT_QUOTED: u8 = 7;
let CK_EXT_QESC: u8 = 8;
let CK_SIZE_LF: u8 = 9;
let CK_DATA: u8 = 10;
let CK_DATA_CR: u8 = 11;
let CK_DATA_LF: u8 = 12;
let CK_TRAILER: u8 = 13;        // at the start of a trailer line
let CK_TRAILER_LINE: u8 = 14;
let CK_TRAILER_LF: u8 = 15;
let CK_END_LF: u8 = 16;
let CK_DONE: u8 = 17;

struct Chunked {
    state: u8,
    digits: i64, size: i64, remaining: i64,
    ext: i64,                   // bytes of the current line's extensions
    trailer: i64,               // bytes of the trailer section so far
    trailer_fields: i64,
    line: i64,                  // where the current trailer line starts in the trailer builder
}

fn chunked_decoder() -> Chunked {
    Chunked { state: CK_SIZE, digits: 0, size: 0, remaining: 0, ext: 0, trailer: 0, trailer_fields: 0, line: 0 }
}

fn chunked_done(d: const Chunked&) -> bool { d.state == CK_DONE }

fn hex_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return (c - 'a') as i64 + 10; }
    if c >= 'A' && c <= 'F' { return (c - 'A') as i64 + 10; }
    return -1;
}

// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text (RFC 9110 §5.6.4)
fn is_qdtext(c: u8) -> bool { c == '\t' || c == ' ' || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || c >= 0x80 }

// Decodes what of a chunked body is in `input`: its data is appended to
// `body`, its trailer section's field lines (each "name: value\r\n",
// checked) to `trailer`. Returns how many bytes it took, which past the
// body's end is less than input.len (the rest is the next message), or
// ERR_BAD_REQUEST, or ERR_FIELDS_TOO_LARGE for a trailer past the limits.
fn chunked_feed(d: Chunked&, lim: const Limits&, input: const u8[:], body: u8[>..]&, trailer: u8[>..]&) -> i64 {
    var i = 0;
    while i < input.len && d.state != CK_DONE {
        let st = d.state;
        if st == CK_DATA {
            let n = if d.remaining < input.len - i { d.remaining } else { input.len - i };
            body.append(input[i..i + n]);
            i += n;
            d.remaining -= n;
            if d.remaining == 0 { d.state = CK_DATA_CR; }
            continue;
        }
        let c = input[i];
        i++;
        if st >= CK_EXT && st <= CK_EXT_QESC {
            d.ext++;
            if d.ext > lim.max_chunk_ext { return ERR_BAD_REQUEST; }
        }
        if st == CK_SIZE {
            let v = hex_value(c);
            if v >= 0 {
                d.digits++;
                if d.digits > 15 { return ERR_BAD_REQUEST; }
                d.size = d.size * 16 + v;
                continue;
            }
            if d.digits == 0 { return ERR_BAD_REQUEST; }
            d.ext = 1;
            if c == '\r' { d.state = CK_SIZE_LF; }
            else if c == ';' { d.state = CK_EXT_NAME0; }
            else if is_ows(c) { d.state = CK_EXT; }
            else { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT {
            if c == ';' { d.state = CK_EXT_NAME0; }
            else if c == '\r' { d.state = CK_SIZE_LF; }
            else if !is_ows(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_NAME0 {
            if is_tchar(c) { d.state = CK_EXT_NAME; }
            else if !is_ows(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_NAME {
            if c == '=' { d.state = CK_EXT_VAL0; }
            else if c == ';' { d.state = CK_EXT_NAME0; }
            else if c == '\r' { d.state = CK_SIZE_LF; }
            else if is_ows(c) { d.state = CK_EXT_AFTER_NAME; }
            else if !is_tchar(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_AFTER_NAME {
            if c == '=' { d.state = CK_EXT_VAL0; }
            else if c == ';' { d.state = CK_EXT_NAME0; }
            else if c == '\r' { d.state = CK_SIZE_LF; }
            else if !is_ows(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_VAL0 {
            if c == '"' { d.state = CK_EXT_QUOTED; }
            else if is_tchar(c) { d.state = CK_EXT_VAL; }
            else if !is_ows(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_VAL {
            if c == ';' { d.state = CK_EXT_NAME0; }
            else if c == '\r' { d.state = CK_SIZE_LF; }
            else if is_ows(c) { d.state = CK_EXT; }
            else if !is_tchar(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_QUOTED {
            if c == '"' { d.state = CK_EXT; }
            else if c == '\\' { d.state = CK_EXT_QESC; }
            else if !is_qdtext(c) { return ERR_BAD_REQUEST; }
        } else if st == CK_EXT_QESC {
            if c == '\t' || c == ' ' || is_field_vchar(c) { d.state = CK_EXT_QUOTED; }
            else { return ERR_BAD_REQUEST; }
        } else if st == CK_SIZE_LF {
            if c != '\n' { return ERR_BAD_REQUEST; }
            if d.size == 0 {
                d.state = CK_TRAILER;
            } else {
                d.remaining = d.size;
                d.state = CK_DATA;
            }
        } else if st == CK_DATA_CR {
            if c != '\r' { return ERR_BAD_REQUEST; }
            d.state = CK_DATA_LF;
        } else if st == CK_DATA_LF {
            if c != '\n' { return ERR_BAD_REQUEST; }
            d.state = CK_SIZE;
            d.digits = 0;
            d.size = 0;
            d.ext = 0;
        } else if st == CK_TRAILER {
            if c == '\r' { d.state = CK_END_LF; continue; }
            if !is_tchar(c) { return ERR_BAD_REQUEST; }       // a field name, not obs-fold or junk
            d.line = trailer.len;
            trailer.push(c);
            d.trailer++;
            d.state = CK_TRAILER_LINE;
        } else if st == CK_TRAILER_LINE {
            if c == '\n' { return ERR_BAD_REQUEST; }
            d.trailer++;
            if d.trailer > lim.max_trailer { return ERR_FIELDS_TOO_LARGE; }
            if c == '\r' { d.state = CK_TRAILER_LF; }
            else { trailer.push(c); }
        } else if st == CK_TRAILER_LF {
            if c != '\n' { return ERR_BAD_REQUEST; }
            let f, ok = field_line(trailer, d.line, trailer.len);
            if !ok { return ERR_BAD_REQUEST; }
            d.trailer_fields++;
            if d.trailer_fields > lim.max_fields { return ERR_FIELDS_TOO_LARGE; }
            trailer.append("\r\n");
            d.state = CK_TRAILER;
        } else if st == CK_END_LF {
            if c != '\n' { return ERR_BAD_REQUEST; }
            d.state = CK_DONE;
        }
    }
    return i;
}

// --- Writing ---------------------------------------------------------------

// A request head: "method target HTTP/1.1", the fields built with
// add_field (which checks them), and the empty line. False, and nothing
// written, if the method is no token or the target has a byte outside
// visible ASCII.
fn write_request_head(out: u8[>..]&, method: const u8[:], target: const u8[:], fields: const u8[:]) -> bool {
    if !is_token(method) || target.len == 0 { return false; }
    for c in target { if c < 0x21 || c > 0x7e { return false; } }
    out.append(method);
    out.push(' ');
    out.append(target);
    out.append(" HTTP/1.1\r\n");
    out.append(fields);
    out.append("\r\n");
    return true;
}

// A response head: "HTTP/1.1 status reason", the fields, the empty line.
fn write_response_head(out: u8[>..]&, status: i64, fields: const u8[:]) -> bool {
    if status < 100 || status > 999 { return false; }
    out.append("HTTP/1.1 ");
    format(out, status);
    out.push(' ');
    out.append(reason_phrase(status));
    out.append("\r\n");
    out.append(fields);
    out.append("\r\n");
    return true;
}

// "Content-Length: n".
fn add_content_length(fields: u8[>..]&, n: i64) {
    fields.append("Content-Length: ");
    format(fields, n);
    fields.append("\r\n");
}

// One chunk of a chunked body; nothing for no data, as a zero-length chunk
// would end the body.
fn write_chunk(out: u8[>..]&, data: const u8[:]) {
    if data.len == 0 { return; }
    format_int(out, data.len, 16, 0, '0');
    out.append("\r\n");
    out.append(data);
    out.append("\r\n");
}

// The last chunk, a trailer section (field lines from add_field, or none)
// and the final CRLF.
fn write_last_chunk(out: u8[>..]&, trailer: const u8[:]) {
    out.append("0\r\n");
    out.append(trailer);
    out.append("\r\n");
}

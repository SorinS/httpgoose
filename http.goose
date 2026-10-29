// http: HTTP semantics (RFC 9110) shared by HTTP/1.1 (http.h1) and, later,
// HTTP/2: the syntax of field names, values, tokens and methods, looking
// fields up in a parsed message, the status codes and their reason
// phrases, and building field sections to send. No sockets: everything
// works on byte strings, so the caller owns the I/O.
//
// A parsed message does not copy what it read. Its parts are spans,
// positions in the caller's buffer: `m[s.pos..s.end]`.

namespace http;

import std;

// A part of the buffer a message was parsed from.
struct Span { pos: i64, end: i64 }

fn span(pos: i64, end: i64) -> Span { Span { pos: pos, end: end } }
fn empty_span() -> Span { Span { pos: 0, end: 0 } }
fn span_len(s: Span) -> i64 { s.end - s.pos }

// One field line: its name, and its value without the whitespace around
// it (RFC 9110 §5.5, RFC 9112 §5.1).
struct Field { name: Span, value: Span }

// Parsed messages' kinds.
let KIND_REQUEST: u8 = 1;
let KIND_RESPONSE: u8 = 2;

// A request or response head: the start line and the field section.
// HTTP/1.1's `len` is how many bytes of the buffer it took, up to and
// including the empty line that ends it.
struct Head {
    kind: u8,
    method: Span, target: Span,           // a request's
    status: i64, reason: Span,            // a response's
    major: u8, minor: u8,                 // HTTP/major.minor
    len: i64,
    fields: Field[>..],
}

fn new_head(kind: u8) -> Head {
    Head {
        kind: kind, method: empty_span(), target: empty_span(), status: 0, reason: empty_span(),
        major: 1, minor: 1, len: 0, fields: [],
    }
}

// --- Syntax (RFC 9110 §5.6) ------------------------------------------------

// tchar: "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" /
// "_" / "`" / "|" / "~" / DIGIT / ALPHA (§5.6.2).
fn is_tchar(c: u8) -> bool {
    if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
           c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

fn is_token(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    for c in s { if !is_tchar(c) { return false; } }
    return true;
}

// field-vchar: VCHAR or obs-text (§5.5).
fn is_field_vchar(c: u8) -> bool { (c >= 0x21 && c <= 0x7e) || c >= 0x80 }

// A field value as it may be sent: field-vchars with single spaces and tabs
// between them, none at either end, and nothing else (no CR, LF or NUL).
fn is_field_value(s: const u8[:]) -> bool {
    for i in s.len {
        let c = s[i];
        if c == ' ' || c == '\t' {
            if i == 0 || i == s.len - 1 { return false; }
        } else if !is_field_vchar(c) {
            return false;
        }
    }
    return true;
}

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// ASCII case-insensitive equality, as field names and tokens compare.
fn eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

fn is_ows(c: u8) -> bool { c == ' ' || c == '\t' }

// --- Fields of a parsed message -------------------------------------------

// The value of the first field named `name`.
fn get(m: const u8[:], h: const Head&, name: const u8[:]) -> Span, bool {
    for f in h.fields {
        if eq_fold(m[f.name.pos..f.name.end], name) { return f.value, true; }
    }
    return empty_span(), false;
}

// How many field lines are named `name`.
fn count(m: const u8[:], h: const Head&, name: const u8[:]) -> i64 {
    var n = 0;
    for f in h.fields { if eq_fold(m[f.name.pos..f.name.end], name) { n++; } }
    return n;
}

// Whether a comma-separated list field named `name` holds `token`, in any
// of its lines and in any case (§5.6.1): Connection's "close", for one.
fn has_token(m: const u8[:], h: const Head&, name: const u8[:], token: const u8[:]) -> bool {
    for f in h.fields {
        if !eq_fold(m[f.name.pos..f.name.end], name) { continue; }
        var found = false;
        each_split(m[f.value.pos..f.value.end], ',') { if eq_fold(trim_ows(it), token) { found = true; } };
        if found { return true; }
    }
    return false;
}

fn trim_ows(s: const u8[:]) -> const u8[:] {
    var a = 0;
    var b = s.len;
    while a < b && is_ows(s[a]) { a++; }
    while b > a && is_ows(s[b - 1]) { b--; }
    return s[a..b];
}

// --- Status codes (§15) ----------------------------------------------------

fn reason_phrase(status: i64) -> const u8[:] {
    if status == 100 { return "Continue"; }
    if status == 101 { return "Switching Protocols"; }
    if status == 200 { return "OK"; }
    if status == 201 { return "Created"; }
    if status == 202 { return "Accepted"; }
    if status == 203 { return "Non-Authoritative Information"; }
    if status == 204 { return "No Content"; }
    if status == 205 { return "Reset Content"; }
    if status == 206 { return "Partial Content"; }
    if status == 300 { return "Multiple Choices"; }
    if status == 301 { return "Moved Permanently"; }
    if status == 302 { return "Found"; }
    if status == 303 { return "See Other"; }
    if status == 304 { return "Not Modified"; }
    if status == 307 { return "Temporary Redirect"; }
    if status == 308 { return "Permanent Redirect"; }
    if status == 400 { return "Bad Request"; }
    if status == 401 { return "Unauthorized"; }
    if status == 403 { return "Forbidden"; }
    if status == 404 { return "Not Found"; }
    if status == 405 { return "Method Not Allowed"; }
    if status == 406 { return "Not Acceptable"; }
    if status == 408 { return "Request Timeout"; }
    if status == 409 { return "Conflict"; }
    if status == 410 { return "Gone"; }
    if status == 411 { return "Length Required"; }
    if status == 412 { return "Precondition Failed"; }
    if status == 413 { return "Content Too Large"; }
    if status == 414 { return "URI Too Long"; }
    if status == 415 { return "Unsupported Media Type"; }
    if status == 416 { return "Range Not Satisfiable"; }
    if status == 417 { return "Expectation Failed"; }
    if status == 421 { return "Misdirected Request"; }
    if status == 422 { return "Unprocessable Content"; }
    if status == 426 { return "Upgrade Required"; }
    if status == 428 { return "Precondition Required"; }
    if status == 429 { return "Too Many Requests"; }
    if status == 431 { return "Request Header Fields Too Large"; }
    if status == 500 { return "Internal Server Error"; }
    if status == 501 { return "Not Implemented"; }
    if status == 502 { return "Bad Gateway"; }
    if status == 503 { return "Service Unavailable"; }
    if status == 504 { return "Gateway Timeout"; }
    if status == 505 { return "HTTP Version Not Supported"; }
    return "";
}

// --- Building field sections ----------------------------------------------

// Appends "name: value\r\n" to a field section being built, if the name is
// a token and the value a valid field value; false, and nothing appended,
// otherwise (a CR or LF in either would let the caller's data start a new
// field or message).
fn add_field(fields: u8[>..]&, name: const u8[:], value: const u8[:]) -> bool {
    if !is_token(name) || !is_field_value(value) { return false; }
    fields.append(name);
    fields.append(": ");
    fields.append(value);
    fields.append("\r\n");
    return true;
}

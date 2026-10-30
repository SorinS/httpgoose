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

let STATUS_CONTINUE: i64 = 100;
let STATUS_SWITCHING_PROTOCOLS: i64 = 101;
let STATUS_PROCESSING: i64 = 102;
let STATUS_EARLY_HINTS: i64 = 103;
let STATUS_OK: i64 = 200;
let STATUS_CREATED: i64 = 201;
let STATUS_ACCEPTED: i64 = 202;
let STATUS_NON_AUTHORITATIVE_INFO: i64 = 203;
let STATUS_NO_CONTENT: i64 = 204;
let STATUS_RESET_CONTENT: i64 = 205;
let STATUS_PARTIAL_CONTENT: i64 = 206;
let STATUS_MULTI_STATUS: i64 = 207;
let STATUS_ALREADY_REPORTED: i64 = 208;
let STATUS_IM_USED: i64 = 226;
let STATUS_MULTIPLE_CHOICES: i64 = 300;
let STATUS_MOVED_PERMANENTLY: i64 = 301;
let STATUS_FOUND: i64 = 302;
let STATUS_SEE_OTHER: i64 = 303;
let STATUS_NOT_MODIFIED: i64 = 304;
let STATUS_USE_PROXY: i64 = 305;
let STATUS_TEMPORARY_REDIRECT: i64 = 307;
let STATUS_PERMANENT_REDIRECT: i64 = 308;
let STATUS_BAD_REQUEST: i64 = 400;
let STATUS_UNAUTHORIZED: i64 = 401;
let STATUS_PAYMENT_REQUIRED: i64 = 402;
let STATUS_FORBIDDEN: i64 = 403;
let STATUS_NOT_FOUND: i64 = 404;
let STATUS_METHOD_NOT_ALLOWED: i64 = 405;
let STATUS_NOT_ACCEPTABLE: i64 = 406;
let STATUS_PROXY_AUTH_REQUIRED: i64 = 407;
let STATUS_REQUEST_TIMEOUT: i64 = 408;
let STATUS_CONFLICT: i64 = 409;
let STATUS_GONE: i64 = 410;
let STATUS_LENGTH_REQUIRED: i64 = 411;
let STATUS_PRECONDITION_FAILED: i64 = 412;
let STATUS_REQUEST_ENTITY_TOO_LARGE: i64 = 413;
let STATUS_URI_TOO_LONG: i64 = 414;
let STATUS_UNSUPPORTED_MEDIA_TYPE: i64 = 415;
let STATUS_REQUESTED_RANGE_NOT_SATISFIABLE: i64 = 416;
let STATUS_EXPECTATION_FAILED: i64 = 417;
let STATUS_TEAPOT: i64 = 418;
let STATUS_MISDIRECTED_REQUEST: i64 = 421;
let STATUS_UNPROCESSABLE_ENTITY: i64 = 422;
let STATUS_LOCKED: i64 = 423;
let STATUS_FAILED_DEPENDENCY: i64 = 424;
let STATUS_TOO_EARLY: i64 = 425;
let STATUS_UPGRADE_REQUIRED: i64 = 426;
let STATUS_PRECONDITION_REQUIRED: i64 = 428;
let STATUS_TOO_MANY_REQUESTS: i64 = 429;
let STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE: i64 = 431;
let STATUS_UNAVAILABLE_FOR_LEGAL_REASONS: i64 = 451;
let STATUS_INTERNAL_SERVER_ERROR: i64 = 500;
let STATUS_NOT_IMPLEMENTED: i64 = 501;
let STATUS_BAD_GATEWAY: i64 = 502;
let STATUS_SERVICE_UNAVAILABLE: i64 = 503;
let STATUS_GATEWAY_TIMEOUT: i64 = 504;
let STATUS_HTTP_VERSION_NOT_SUPPORTED: i64 = 505;
let STATUS_VARIANT_ALSO_NEGOTIATES: i64 = 506;
let STATUS_INSUFFICIENT_STORAGE: i64 = 507;
let STATUS_LOOP_DETECTED: i64 = 508;
let STATUS_NOT_EXTENDED: i64 = 510;
let STATUS_NETWORK_AUTHENTICATION_REQUIRED: i64 = 511;

// The class of a status: 1 for 1xx (informational) up to 5 for 5xx; 0 for
// a code out of range.
fn status_class(status: i64) -> i64 { if status >= 100 && status <= 599 { status / 100 } else { 0 } }


// The reason phrases of Go's http.StatusText: the IANA registry's codes
// (RFC 9110 §15 and the RFCs that added the rest), "" for others.
fn reason_phrase(status: i64) -> const u8[:] {
    if status == 100 { return "Continue"; }
    if status == 101 { return "Switching Protocols"; }
    if status == 102 { return "Processing"; }
    if status == 103 { return "Early Hints"; }
    if status == 200 { return "OK"; }
    if status == 201 { return "Created"; }
    if status == 202 { return "Accepted"; }
    if status == 203 { return "Non-Authoritative Information"; }
    if status == 204 { return "No Content"; }
    if status == 205 { return "Reset Content"; }
    if status == 206 { return "Partial Content"; }
    if status == 207 { return "Multi-Status"; }
    if status == 208 { return "Already Reported"; }
    if status == 226 { return "IM Used"; }
    if status == 300 { return "Multiple Choices"; }
    if status == 301 { return "Moved Permanently"; }
    if status == 302 { return "Found"; }
    if status == 303 { return "See Other"; }
    if status == 304 { return "Not Modified"; }
    if status == 305 { return "Use Proxy"; }
    if status == 307 { return "Temporary Redirect"; }
    if status == 308 { return "Permanent Redirect"; }
    if status == 400 { return "Bad Request"; }
    if status == 401 { return "Unauthorized"; }
    if status == 402 { return "Payment Required"; }
    if status == 403 { return "Forbidden"; }
    if status == 404 { return "Not Found"; }
    if status == 405 { return "Method Not Allowed"; }
    if status == 406 { return "Not Acceptable"; }
    if status == 407 { return "Proxy Authentication Required"; }
    if status == 408 { return "Request Timeout"; }
    if status == 409 { return "Conflict"; }
    if status == 410 { return "Gone"; }
    if status == 411 { return "Length Required"; }
    if status == 412 { return "Precondition Failed"; }
    if status == 413 { return "Request Entity Too Large"; }
    if status == 414 { return "Request URI Too Long"; }
    if status == 415 { return "Unsupported Media Type"; }
    if status == 416 { return "Requested Range Not Satisfiable"; }
    if status == 417 { return "Expectation Failed"; }
    if status == 418 { return "I'm a teapot"; }
    if status == 421 { return "Misdirected Request"; }
    if status == 422 { return "Unprocessable Entity"; }
    if status == 423 { return "Locked"; }
    if status == 424 { return "Failed Dependency"; }
    if status == 425 { return "Too Early"; }
    if status == 426 { return "Upgrade Required"; }
    if status == 428 { return "Precondition Required"; }
    if status == 429 { return "Too Many Requests"; }
    if status == 431 { return "Request Header Fields Too Large"; }
    if status == 451 { return "Unavailable For Legal Reasons"; }
    if status == 500 { return "Internal Server Error"; }
    if status == 501 { return "Not Implemented"; }
    if status == 502 { return "Bad Gateway"; }
    if status == 503 { return "Service Unavailable"; }
    if status == 504 { return "Gateway Timeout"; }
    if status == 505 { return "HTTP Version Not Supported"; }
    if status == 506 { return "Variant Also Negotiates"; }
    if status == 507 { return "Insufficient Storage"; }
    if status == 508 { return "Loop Detected"; }
    if status == 510 { return "Not Extended"; }
    if status == 511 { return "Network Authentication Required"; }
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

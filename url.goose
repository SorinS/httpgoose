// http.url: URLs (RFC 3986) as Go's net/url reads them: parsing, the
// parts of one, resolving a reference against a base (§5.2), percent-
// encoding, queries and forms, IP addresses, and the ASCII form of a
// host name (Punycode, RFC 3492).
//
// A Url holds its text, `s`, and spans into it; the parts keep their
// percent-encoding as written. Parsing accepts and refuses what Go's
// url.Parse does, and resolution follows Go's ResolveReference, which
// gives RFC 3986 §5.4's results. Where they part, the request target sent
// on the wire escapes what RFC 9112 does not allow in one (a space, a
// quote, a byte past 0x7f) instead of passing it along as Go does.
//
//   let u, err = http::url_parse("https://user@example.com:8443/a/b?q=1#top");
//   if err == 0 {
//       let next = http::url_resolve(u, "../c?x");   // https://user@example.com:8443/c?x
//       http::request_target(next, out);            // /c?x
//   }

namespace http;

import std;
import http;

struct Url {
    scheme: Span,                   // lowercase; empty for a relative reference
    opaque: bool,                   // scheme ":" without a "/" after it: path is the opaque part
    has_authority: bool,            // "//" authority
    has_user: bool, has_password: bool,
    user: Span, password: Span,     // as written, still percent-encoded
    host: Span,                     // without an IPv6 literal's brackets; a zone stays "%25..."
    ipv6: bool,                     // the host was in brackets
    has_port: bool,                 // a ":" after the host, its digits perhaps empty
    port: Span,
    path: Span,
    has_query: bool, query: Span,   // has_query: a "?" was there, the query perhaps empty
    has_fragment: bool, fragment: Span,
    s: u8[>..],
}

// url_parse's errors.
let URL_OK: i64 = 0;
let URL_ERR_CONTROL: i64 = 1;       // an ASCII control byte
let URL_ERR_SCHEME: i64 = 2;        // ":" first: no scheme
let URL_ERR_COLON: i64 = 3;         // a relative path's first segment has a colon
let URL_ERR_ESCAPE: i64 = 4;        // a "%" not followed by two hex digits, or one a host may not have
let URL_ERR_USERINFO: i64 = 5;
let URL_ERR_HOST: i64 = 6;          // a byte a host may not have
let URL_ERR_PORT: i64 = 7;          // the port is not digits
let URL_ERR_IP_LITERAL: i64 = 8;    // brackets around something not an IPv6 address
let URL_ERR_NOT_HTTP: i64 = 9;      // a client's URL that is not http or https with a host

fn url_error_text(e: i64) -> const u8[:] {
    if e == URL_ERR_CONTROL { return "invalid control character in URL"; }
    if e == URL_ERR_SCHEME { return "missing protocol scheme"; }
    if e == URL_ERR_COLON { return "first path segment in URL cannot contain colon"; }
    if e == URL_ERR_ESCAPE { return "invalid URL escape"; }
    if e == URL_ERR_USERINFO { return "invalid userinfo"; }
    if e == URL_ERR_HOST { return "invalid character in host name"; }
    if e == URL_ERR_PORT { return "invalid port after host"; }
    if e == URL_ERR_IP_LITERAL { return "invalid IP-literal"; }
    if e == URL_ERR_NOT_HTTP { return "not an http or https URL with a host"; }
    return "";
}

fn empty_url() -> Url {
    Url {
        scheme: empty_span(), opaque: false, has_authority: false, has_user: false, has_password: false,
        user: empty_span(), password: empty_span(), host: empty_span(), ipv6: false, has_port: false,
        port: empty_span(), path: empty_span(), has_query: false, query: empty_span(), has_fragment: false,
        fragment: empty_span(), s: [],
    }
}

// The parts of a URL, as slices of some text, before they are copied into
// a Url's own.
struct UrlParts {
    scheme: Span, opaque: bool, has_authority: bool, has_user: bool, has_password: bool,
    user: Span, password: Span, host: Span, ipv6: bool, has_port: bool, port: Span,
    path: Span, has_query: bool, query: Span, has_fragment: bool, fragment: Span,
}

fn no_parts() -> UrlParts {
    UrlParts {
        scheme: empty_span(), opaque: false, has_authority: false, has_user: false, has_password: false,
        user: empty_span(), password: empty_span(), host: empty_span(), ipv6: false, has_port: false,
        port: empty_span(), path: empty_span(), has_query: false, query: empty_span(), has_fragment: false,
        fragment: empty_span(),
    }
}

fn put_part(u: Url&, t: const u8[:], sp: Span) -> Span {
    let pos = u.s.len;
    u.s.append(t[sp.pos..sp.end]);
    return span(pos, u.s.len);
}

// The URL of those parts, its text written the way they say. A path that
// would start with "//" without an authority gets "/." before it (§5.2.4's
// output must not look like an authority).
fn url_of(t: const u8[:], p: const UrlParts&) -> Url {
    var u = empty_url();
    if span_len(p.scheme) > 0 {
        let pos = u.s.len;
        for c in t[p.scheme.pos..p.scheme.end] { u.s.push(lower(c)); }
        u.scheme = span(pos, u.s.len);
        u.s.push(':');
    }
    u.opaque = p.opaque;
    if p.has_authority {
        u.has_authority = true;
        u.s.append("//");
        if p.has_user {
            u.has_user = true;
            u.user = put_part(u, t, p.user);
            if p.has_password {
                u.has_password = true;
                u.s.push(':');
                u.password = put_part(u, t, p.password);
            }
            u.s.push('@');
        }
        u.ipv6 = p.ipv6;
        if p.ipv6 { u.s.push('['); }
        u.host = put_part(u, t, p.host);
        if p.ipv6 { u.s.push(']'); }
        if p.has_port {
            u.has_port = true;
            u.s.push(':');
            u.port = put_part(u, t, p.port);
        }
    } else if !p.opaque && span_len(p.path) >= 2 && t[p.path.pos] == '/' && t[p.path.pos + 1] == '/' {
        u.s.append("/.");
    }
    u.path = put_part(u, t, p.path);
    if p.has_query {
        u.has_query = true;
        u.s.push('?');
        u.query = put_part(u, t, p.query);
    }
    if p.has_fragment {
        u.has_fragment = true;
        u.s.push('#');
        u.fragment = put_part(u, t, p.fragment);
    }
    return u;
}

fn part(u: const Url&, sp: Span) -> const u8[:] { u.s[sp.pos..sp.end] }

fn url_scheme(u: const Url&) -> const u8[:] { part(u, u.scheme) }
fn url_host(u: const Url&) -> const u8[:] { part(u, u.host) }
fn url_port_text(u: const Url&) -> const u8[:] { part(u, u.port) }
fn url_path(u: const Url&) -> const u8[:] { part(u, u.path) }
fn url_query(u: const Url&) -> const u8[:] { part(u, u.query) }
fn url_fragment(u: const Url&) -> const u8[:] { part(u, u.fragment) }

// The URL as text.
fn url_text(u: const Url&) -> const u8[:] { u.s[..] }

fn is_abs(u: const Url&) -> bool { span_len(u.scheme) > 0 }

// --- Percent-encoding ------------------------------------------------------

fn url_hex(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

fn is_alnum(c: u8) -> bool { (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') }

fn is_unreserved(c: u8) -> bool { is_alnum(c) || c == '-' || c == '.' || c == '_' || c == '~' }

fn is_sub_delim(c: u8) -> bool {
    c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' ||
    c == ',' || c == ';' || c == '='
}

// Go's encodings: which bytes each part of a URL escapes.
let ENC_PATH: u8 = 1;
let ENC_PATH_SEGMENT: u8 = 2;
let ENC_HOST: u8 = 3;
let ENC_ZONE: u8 = 4;
let ENC_USER_PASSWORD: u8 = 5;
let ENC_QUERY_COMPONENT: u8 = 6;
let ENC_FRAGMENT: u8 = 7;

fn should_escape(c: u8, mode: u8) -> bool {
    if is_alnum(c) { return false; }
    if mode == ENC_HOST || mode == ENC_ZONE {
        if is_sub_delim(c) || c == ':' || c == '[' || c == ']' || c == '<' || c == '>' || c == '"' { return false; }
    }
    if c == '-' || c == '_' || c == '.' || c == '~' { return false; }
    if c == '$' || c == '&' || c == '+' || c == ',' || c == '/' || c == ':' || c == ';' || c == '=' || c == '?' || c == '@' {
        if mode == ENC_PATH { return c == '?'; }
        if mode == ENC_PATH_SEGMENT { return c == '/' || c == ';' || c == ',' || c == '?'; }
        if mode == ENC_USER_PASSWORD { return c == '@' || c == '/' || c == '?' || c == ':'; }
        if mode == ENC_QUERY_COMPONENT { return true; }
        if mode == ENC_FRAGMENT { return false; }
    }
    if mode == ENC_FRAGMENT && (c == '!' || c == '(' || c == ')' || c == '*') { return false; }
    return true;
}

let UPPER_HEX: const u8[:] = "0123456789ABCDEF";

fn put_escaped(out: u8[>..]&, c: u8) {
    out.push('%');
    out.push(UPPER_HEX[c >> 4]);
    out.push(UPPER_HEX[c & 15]);
}

// Go's escape: QueryEscape (a space becomes "+") and PathEscape.
fn escape_to(out: u8[>..]&, s: const u8[:], mode: u8) {
    for c in s {
        if c == ' ' && mode == ENC_QUERY_COMPONENT { out.push('+'); }
        else if should_escape(c, mode) { put_escaped(out, c); }
        else { out.push(c); }
    }
}

fn query_escape(out: u8[>..]&, s: const u8[:]) { escape_to(out, s, ENC_QUERY_COMPONENT); }
fn path_escape(out: u8[>..]&, s: const u8[:]) { escape_to(out, s, ENC_PATH_SEGMENT); }

// Whether Go's unescape takes s in this mode: each "%" has two hex digits
// after it, and a host has only the bytes a host may (a "%" escape there
// only for a byte past 0x7f, or "%25").
fn check_escapes(s: const u8[:], mode: u8) -> i64 {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '%' {
            if i + 2 >= s.len || url_hex(s[i + 1]) < 0 || url_hex(s[i + 2]) < 0 { return URL_ERR_ESCAPE; }
            let v = (url_hex(s[i + 1]) * 16 + url_hex(s[i + 2])) as! u8;
            let is25 = s[i + 1] == '2' && s[i + 2] == '5';
            if mode == ENC_HOST && url_hex(s[i + 1]) < 8 && !is25 { return URL_ERR_ESCAPE; }
            if mode == ENC_ZONE && !is25 && v != ' ' && should_escape(v, ENC_HOST) { return URL_ERR_ESCAPE; }
            i += 3;
        } else {
            if (mode == ENC_HOST || mode == ENC_ZONE) && c < 0x80 && should_escape(c, mode) { return URL_ERR_HOST; }
            i++;
        }
    }
    return URL_OK;
}

// Percent-decoding: false, and nothing appended, at a "%" without two hex
// digits. A query component's "+" is a space.
fn unescape_to(out: u8[>..]&, s: const u8[:], query: bool) -> bool {
    var i = 0;
    while i < s.len {
        if s[i] == '%' && (i + 2 >= s.len || url_hex(s[i + 1]) < 0 || url_hex(s[i + 2]) < 0) { return false; }
        i += if s[i] == '%' { 3 } else { 1 };
    }
    i = 0;
    while i < s.len {
        let c = s[i];
        if c == '%' {
            out.push((url_hex(s[i + 1]) * 16 + url_hex(s[i + 2])) as! u8);
            i += 3;
        } else {
            out.push(if c == '+' && query { ' ' } else { c });
            i++;
        }
    }
    return true;
}

fn query_unescape(out: u8[>..]&, s: const u8[:]) -> bool { unescape_to(out, s, true) }
fn path_unescape(out: u8[>..]&, s: const u8[:]) -> bool { unescape_to(out, s, false) }

// --- Parsing ---------------------------------------------------------------

fn has_ctl(s: const u8[:]) -> bool {
    for c in s { if c < ' ' || c == 0x7f { return true; } }
    return false;
}

fn last_index(s: const u8[:], c: u8) -> i64 {
    var i = s.len - 1;
    while i >= 0 { if s[i] == c { return i; } i--; }
    return -1;
}

// Go's getScheme: the length of the scheme, 0 for none, -1 for an error.
fn scheme_len(s: const u8[:]) -> i64 {
    for i in s.len {
        let c = s[i];
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') { continue; }
        if (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' {
            if i == 0 { return 0; }
            continue;
        }
        if c == ':' { return if i == 0 { -1 } else { i }; }
        return 0;
    }
    return 0;
}

fn valid_optional_port(p: const u8[:]) -> bool {
    if p.len == 0 { return true; }
    if p[0] != ':' { return false; }
    for c in p[1..] { if c < '0' || c > '9' { return false; } }
    return true;
}

fn valid_userinfo(s: const u8[:]) -> bool {
    for c in s {
        if is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '%' || c == '@' { continue; }
        return false;
    }
    return true;
}

// The authority, t[a..b]: userinfo, host, port into p.
fn parse_authority(t: const u8[:], a: i64, b: i64, scheme: const u8[:], p: UrlParts&) -> i64 {
    let auth = t[a..b];
    let at = last_index(auth, '@');
    let hs = if at < 0 { a } else { a + at + 1 };
    let e = parse_host(t, hs, b, scheme, p);
    if e != URL_OK { return e; }
    if at >= 0 {
        let ui = t[a..a + at];
        if !valid_userinfo(ui) { return URL_ERR_USERINFO; }
        p.has_user = true;
        let colon = position(ui, ':');
        if colon < 0 {
            if check_escapes(ui, ENC_USER_PASSWORD) != URL_OK { return URL_ERR_ESCAPE; }
            p.user = span(a, a + at);
        } else {
            if check_escapes(ui[..colon], ENC_USER_PASSWORD) != URL_OK { return URL_ERR_ESCAPE; }
            if check_escapes(ui[colon + 1..], ENC_USER_PASSWORD) != URL_OK { return URL_ERR_ESCAPE; }
            p.user = span(a, a + colon);
            p.has_password = true;
            p.password = span(a + colon + 1, a + at);
        }
    }
    return URL_OK;
}

// Go's parseHost on t[a..b].
fn parse_host(t: const u8[:], a: i64, b: i64, scheme: const u8[:], p: UrlParts&) -> i64 {
    let h = t[a..b];
    let open = last_index(h, '[');
    if open > 0 { return URL_ERR_IP_LITERAL; }
    if open == 0 {
        let close = last_index(h, ']');
        if close < 0 { return URL_ERR_IP_LITERAL; }
        let cport = h[close + 1..];
        if !valid_optional_port(cport) { return URL_ERR_PORT; }
        let name = h[1..close];
        let z = find(name, "%25");
        var addr: u8[>..] = [];
        if z >= 0 {
            let e1 = check_escapes(name[..z], ENC_HOST);
            if e1 != URL_OK { return e1; }
            let e2 = check_escapes(name[z..], ENC_ZONE);
            if e2 != URL_OK { return e2; }
            unescape_to(addr, name, false);
        } else {
            let e1 = check_escapes(name, ENC_HOST);
            if e1 != URL_OK { return e1; }
            unescape_to(addr, name, false);
        }
        let ip, kind = parse_ip_zone(addr);
        if kind != 6 { return URL_ERR_IP_LITERAL; }
        p.ipv6 = true;
        p.host = span(a + 1, a + close);
        if cport.len > 0 { p.has_port = true; p.port = span(a + close + 2, b); }
        return URL_OK;
    }
    var i = position(h, ':');
    if i >= 0 {
        let last = last_index(h, ':');
        if last != i && scheme != "http" && scheme != "https" { i = last; }
        if !valid_optional_port(h[i..]) { return URL_ERR_PORT; }
    }
    let name = if i >= 0 { h[..i] } else { h };
    let e = check_escapes(name, ENC_HOST);
    if e != URL_OK { return e; }
    p.host = span(a, a + name.len);
    if i >= 0 { p.has_port = true; p.port = span(a + i + 1, b); }
    return URL_OK;
}

// A URL or a relative reference, as Go's url.Parse takes it.
fn url_parse(text: const u8[:]) -> Url, i64 {
    var p = no_parts();
    var end = text.len;
    let hash = position(text, '#');
    if hash >= 0 {
        end = hash;
        if check_escapes(text[hash + 1..], ENC_FRAGMENT) != URL_OK { return empty_url(), URL_ERR_ESCAPE; }
        if hash + 1 < text.len {
            p.has_fragment = true;
            p.fragment = span(hash + 1, text.len);
        }
    }
    let t = text[..end];
    if has_ctl(t) { return empty_url(), URL_ERR_CONTROL; }
    var pos = 0;
    let sl = scheme_len(t);
    if sl < 0 { return empty_url(), URL_ERR_SCHEME; }
    if sl > 0 { p.scheme = span(0, sl); pos = sl + 1; }
    var scheme: u8[>..] = [];
    for c in t[p.scheme.pos..p.scheme.end] { scheme.push(lower(c)); }
    // The query: after the first "?" (a lone "?" at the end forces an empty one).
    var rest_end = end;
    let q = position(t[pos..], '?');
    if q >= 0 {
        rest_end = pos + q;
        p.has_query = true;
        p.query = span(rest_end + 1, end);
    }
    let rest = t[pos..rest_end];
    if rest.len == 0 || rest[0] != '/' {
        if sl > 0 {
            p.opaque = true;
            p.path = span(pos, rest_end);
            return url_of(text, p), URL_OK;
        }
        var seg = position(rest, '/');
        if seg < 0 { seg = rest.len; }
        if position(rest[..seg], ':') >= 0 { return empty_url(), URL_ERR_COLON; }
    }
    var path_start = pos;
    if starts_with(rest, "//") && (sl > 0 || !starts_with(rest, "///")) {
        let a = pos + 2;
        var b = position(t[a..rest_end], '/');
        b = if b < 0 { rest_end } else { a + b };
        let e = parse_authority(t, a, b, scheme, p);
        if e != URL_OK { return empty_url(), e; }
        p.has_authority = true;
        path_start = b;
    }
    let pe = check_escapes(t[path_start..rest_end], ENC_PATH);
    if pe != URL_OK { return empty_url(), pe; }
    p.path = span(path_start, rest_end);
    // The query's escapes are not checked (Go keeps RawQuery as it is).
    return url_of(text, p), URL_OK;
}

// --- Resolving references (§5.2, as Go's ResolveReference) ----------------

// Go's resolvePath: the merged path with its dot segments removed.
fn resolve_path(base: const u8[:], r: const u8[:]) -> u8[>..] {
    var full: u8[>..] = [];
    if r.len == 0 {
        full.append(base);
    } else if r[0] != '/' {
        let i = last_index(base, '/');
        full.append(base[..i + 1]);
        full.append(r);
    } else {
        full.append(r);
    }
    var dst: u8[>..] = [];
    if full.len == 0 { return dst; }
    dst.push('/');
    var first = true;
    var start = 0;
    var last_elem_dot = false;
    var done = false;
    while !done {
        var slash = position(full[start..], '/');
        var elem_end = full.len;
        if slash < 0 { done = true; } else { elem_end = start + slash; }
        let elem = full[start..elem_end];
        last_elem_dot = elem == "." || elem == "..";
        if elem == "." {
            first = false;
        } else if elem == ".." {
            let i = last_index(dst[1..], '/');
            if i >= 0 { dst.resize(i + 1); } else { dst.resize(1); }
            first = dst.len == 1;
        } else {
            if !first { dst.push('/'); }
            dst.append(elem);
            first = false;
        }
        start = elem_end + 1;
    }
    if last_elem_dot { dst.push('/'); }
    if dst.len > 1 && dst[1] == '/' {
        var out: u8[>..] = [];
        out.append(dst[1..]);
        return out;
    }
    return dst;
}

// Go's ResolveReference: the reference r taken relative to base u.
fn url_resolve_ref(u: const Url&, r: const Url&) -> Url {
    // The parts are written into one text: r's, then u's, then a resolved path.
    var t: u8[>..] = [];
    t.append(r.s);
    let off = t.len;
    t.append(u.s);
    var p = no_parts();
    p.scheme = if is_abs(r) { r.scheme } else { span(u.scheme.pos + off, u.scheme.end + off) };
    p.has_query = r.has_query;
    p.query = r.query;
    p.has_fragment = r.has_fragment;
    p.fragment = r.fragment;
    if is_abs(r) || r.has_authority {
        p.opaque = r.opaque;
        p.has_authority = r.has_authority;
        p.has_user = r.has_user; p.user = r.user;
        p.has_password = r.has_password; p.password = r.password;
        p.host = r.host; p.ipv6 = r.ipv6; p.has_port = r.has_port; p.port = r.port;
        if r.opaque {
            p.path = r.path;
        } else {
            let rp = resolve_path(part(r, r.path), "");
            let pp = t.len;
            t.append(rp);
            p.path = span(pp, t.len);
        }
        return url_of(t, p);
    }
    let ref_path_empty = span_len(r.path) == 0;
    if ref_path_empty && !r.has_query {
        p.has_query = u.has_query;
        p.query = span(u.query.pos + off, u.query.end + off);
        if !r.has_fragment {
            p.has_fragment = u.has_fragment;
            p.fragment = span(u.fragment.pos + off, u.fragment.end + off);
        }
    }
    if ref_path_empty && u.opaque {
        p.opaque = true;
        p.path = span(u.path.pos + off, u.path.end + off);
        return url_of(t, p);
    }
    p.has_authority = u.has_authority;
    p.has_user = u.has_user; p.user = span(u.user.pos + off, u.user.end + off);
    p.has_password = u.has_password; p.password = span(u.password.pos + off, u.password.end + off);
    p.host = span(u.host.pos + off, u.host.end + off);
    p.ipv6 = u.ipv6;
    p.has_port = u.has_port;
    p.port = span(u.port.pos + off, u.port.end + off);
    let rp = resolve_path(if u.opaque { "" } else { part(u, u.path) }, part(r, r.path));
    let pp = t.len;
    t.append(rp);
    p.path = span(pp, t.len);
    return url_of(t, p);
}

// The reference `text` (a Location field's value, a link) taken relative
// to u, as Go's u.Parse(text).
fn url_resolve(u: const Url&, text: const u8[:]) -> Url, i64 {
    let r, e = url_parse(text);
    if e != URL_OK { return empty_url(), e; }
    return url_resolve_ref(u, r), URL_OK;
}

// --- For HTTP --------------------------------------------------------------

// An http or https URL with a host: what a client can request.
fn url_check_http(u: const Url&) -> i64 {
    let sc = url_scheme(u);
    if (sc != "http" && sc != "https") || u.opaque || !u.has_authority || span_len(u.host) == 0 { return URL_ERR_NOT_HTTP; }
    return URL_OK;
}

fn url_https(u: const Url&) -> bool { url_scheme(u) == "https" }

fn default_port(scheme: const u8[:]) -> i64 {
    if scheme == "http" { return 80; }
    if scheme == "https" { return 443; }
    if scheme == "socks5" || scheme == "socks5h" { return 1080; }
    return 0;
}

// The port to connect to: the URL's, else the scheme's; -1 if out of range.
fn url_port(u: const Url&) -> i64 {
    let pt = url_port_text(u);
    if pt.len == 0 { return default_port(url_scheme(u)); }
    var n: i64 = 0;
    for c in pt {
        n = n * 10 + (c - '0');
        if n > 65535 { return -1; }
    }
    return if n == 0 { -1 } else { n };
}

// The host name, its escapes decoded (an IPv6 zone's "%25" is "%").
fn url_hostname(u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    unescape_to(out, url_host(u), false);
    return out;
}

// The user name and password, decoded.
fn url_username(u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    unescape_to(out, part(u, u.user), false);
    return out;
}

fn url_password(u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    unescape_to(out, part(u, u.password), false);
    return out;
}

// The host name to resolve and to send: decoded, an IPv6 address without
// its zone, a name in its ASCII form (Punycode for non-ASCII labels, as
// Go's cookiejar does it: ASCII letters lowered, other mapping not done).
// False for a name that cannot be written so.
fn url_ascii_host(u: const Url&) -> u8[>..], bool {
    let h = url_hostname(u);
    if u.ipv6 {
        var out: u8[>..] = [];
        let z = position(h, '%');
        out.append(if z >= 0 { h[..z] } else { h[..] });
        return out, true;
    }
    return to_ascii_host(h);
}

// Bytes RFC 9112 allows in a request target as they are: pchar, "/", and
// "?" in the query. Others go escaped.
fn target_byte_ok(c: u8, query: bool) -> bool {
    if is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@' || c == '/' || c == '%' { return true; }
    return query && c == '?';
}

fn put_target_part(out: u8[>..]&, s: const u8[:], query: bool) {
    for c in s {
        if target_byte_ok(c, query) { out.push(c); } else { put_escaped(out, c); }
    }
}

// The origin-form request target: the path ("/" if empty) and the query.
fn request_target(u: const Url&, out: u8[>..]&) {
    let p = url_path(u);
    if p.len == 0 { out.push('/'); } else { put_target_part(out, p, false); }
    if u.has_query {
        out.push('?');
        put_target_part(out, url_query(u), true);
    }
}

// The absolute-form target a request to a proxy has: the URL without its
// userinfo and fragment.
fn absolute_target(u: const Url&, out: u8[>..]&) {
    out.append(url_scheme(u));
    out.append("://");
    host_port_field(u, out);
    request_target(u, out);
}

// The Host field's value: the host, in brackets for IPv6 without a zone,
// in ASCII form, and the port if the URL has one. False if the host has
// no ASCII form.
fn host_port_field(u: const Url&, out: u8[>..]&) -> bool {
    let h, ok = url_ascii_host(u);
    if !ok { return false; }
    if u.ipv6 { out.push('['); }
    out.append(h);
    if u.ipv6 { out.push(']'); }
    if span_len(u.port) > 0 { out.push(':'); out.append(url_port_text(u)); }
    return true;
}

// The URL's text without userinfo and fragment (a Referer, RFC 9110 §10.1.3).
fn url_referer(u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    if u.has_user {
        out.append(u.s[..u.user.pos]);
        let hs = if u.ipv6 { u.host.pos - 1 } else { u.host.pos };
        out.append(u.s[hs..]);
    } else {
        out.append(u.s[..]);
    }
    if u.has_fragment {
        out.resize(out.len - span_len(u.fragment) - 1);
    }
    return out;
}

// The URL with its password replaced by "xxxxx", for messages (Go's Redacted).
fn url_redacted(u: const Url&) -> u8[>..] {
    var out: u8[>..] = [];
    if !u.has_password { out.append(u.s[..]); return out; }
    out.append(u.s[..u.password.pos]);
    out.append("xxxxx");
    out.append(u.s[u.password.end..]);
    return out;
}

// --- Queries and forms -----------------------------------------------------

// Appends name=value to a query or form being built, escaped as Go's
// Values.Encode does, with "&" before it unless it is the first.
fn form_add(q: u8[>..]&, name: const u8[:], value: const u8[:]) {
    if q.len > 0 { q.push('&'); }
    query_escape(q, name);
    q.push('=');
    query_escape(q, value);
}

// The first value of `name` in a query (pairs split at "&", "+" a space),
// decoded; false if there is none. Pairs that do not decode are skipped,
// as are pairs with a ";" (Go's ParseQuery refuses them).
fn query_value(q: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var found = false;
    each_split(q, '&') {
        let pair = it;
        if !found && pair.len > 0 && position(pair, ';') < 0 {
            let eq = position(pair, '=');
            let k = if eq < 0 { pair } else { pair[..eq] };
            var key: u8[>..] = [];
            if query_unescape(key, k) && key[..] == name {
                var v: u8[>..] = [];
                if eq < 0 || query_unescape(v, pair[eq + 1..]) {
                    out.append(v);
                    found = true;
                }
            }
        }
    };
    return out, found;
}

// --- IP addresses ----------------------------------------------------------

// An IPv4 address in dotted decimal, Go's netip way: four parts, no
// leading zeros, each at most 255.
fn parse_ip4(s: const u8[:], out: u8[:]) -> bool {
    var part = 0;
    var digits = 0;
    var v: i64 = 0;
    for i in s.len {
        let c = s[i];
        if c >= '0' && c <= '9' {
            if digits == 1 && v == 0 { return false; }
            v = v * 10 + (c - '0');
            digits++;
            if v > 255 { return false; }
        } else if c == '.' {
            if digits == 0 || part == 3 { return false; }
            out[part] = v as! u8;
            part++;
            digits = 0;
            v = 0;
        } else {
            return false;
        }
    }
    if digits == 0 || part != 3 { return false; }
    out[3] = v as! u8;
    return true;
}

// An IP address: 4 for IPv4, 6 for IPv6 (an IPv4 tail allowed), 0 for
// neither; the 16 bytes (IPv4 as ::ffff:a.b.c.d). No zone. Go's netip
// rules: up to four hex digits a group, "::" for at least one group.
fn parse_ip(s: const u8[:]) -> u8[16], i64 {
    var ip: u8[16] = [0; 16];
    var v4: u8[4] = [0; 4];
    if parse_ip4(s, v4) {
        ip[10] = 0xff; ip[11] = 0xff;
        for i in 4 { ip[12 + i] = v4[i]; }
        return ip, 4;
    }
    var ellipsis = -1;
    var p = 0;                      // the next byte of s
    if s.len >= 2 && s[0] == ':' && s[1] == ':' {
        ellipsis = 0;
        p = 2;
        if p == s.len { return ip, 6; }
    }
    var i = 0;                      // bytes of ip written
    while i < 16 {
        var off = 0;
        var acc: i64 = 0;
        while p + off < s.len {
            let v = url_hex(s[p + off]);
            if v < 0 { break; }
            if off > 3 { return ip, 0; }
            acc = acc * 16 + v;
            off++;
        }
        if off == 0 { return ip, 0; }
        if p + off < s.len && s[p + off] == '.' {
            if (ellipsis < 0 && i != 12) || i + 4 > 16 { return ip, 0; }
            if !parse_ip4(s[p..], v4) { return ip, 0; }
            for k in 4 { ip[i + k] = v4[k]; }
            i += 4;
            p = s.len;
            break;
        }
        ip[i] = (acc >> 8) as! u8;
        ip[i + 1] = (acc & 0xff) as! u8;
        i += 2;
        p += off;
        if p == s.len { break; }
        if s[p] != ':' || p + 1 == s.len { return ip, 0; }
        p++;
        if s[p] == ':' {
            if ellipsis >= 0 { return ip, 0; }
            ellipsis = i;
            p++;
            if p == s.len { break; }
        }
    }
    if p != s.len { return ip, 0; }
    if i < 16 {
        if ellipsis < 0 { return ip, 0; }
        let n = 16 - i;
        var k = i - 1;
        while k >= ellipsis { ip[k + n] = ip[k]; k--; }
        for z in ellipsis..ellipsis + n { ip[z] = 0; }
    } else if ellipsis >= 0 {
        return ip, 0;
    }
    return ip, 6;
}

// An IP address with an IPv6 zone allowed ("fe80::1%en0"; the zone not empty).
fn parse_ip_zone(s: const u8[:]) -> u8[16], i64 {
    let z = position(s, '%');
    if z < 0 { return parse_ip(s); }
    let ip, kind = parse_ip(s[..z]);
    if kind != 6 || z + 1 == s.len { return ip, 0; }
    return ip, 6;
}

fn is_ip(s: const u8[:]) -> bool {
    let ip, kind = parse_ip_zone(s);
    return kind != 0;
}

fn ip_is_loopback(ip: const u8[:], kind: i64) -> bool {
    if kind == 0 { return false; }
    var v4mapped = true;
    for i in 10 { if ip[i] != 0 { v4mapped = false; } }
    if v4mapped && ip[10] == 0xff && ip[11] == 0xff { return ip[12] == 127; }
    if kind != 6 { return false; }
    for i in 15 { if ip[i] != 0 { return false; } }
    return ip[15] == 1;
}

// --- ASCII host names (Punycode, RFC 3492) ---------------------------------

let PUNY_BASE: i64 = 36;
let PUNY_TMIN: i64 = 1;
let PUNY_TMAX: i64 = 26;
let PUNY_SKEW: i64 = 38;
let PUNY_DAMP: i64 = 700;
let PUNY_INITIAL_BIAS: i64 = 72;
let PUNY_INITIAL_N: i64 = 128;

fn puny_digit(d: i64) -> u8 { if d < 26 { ('a' + d) as! u8 } else { ('0' + d - 26) as! u8 } }

fn puny_adapt(delta0: i64, num_points: i64, first: bool) -> i64 {
    var delta = if first { delta0 / PUNY_DAMP } else { delta0 / 2 };
    delta += delta / num_points;
    var k: i64 = 0;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    return k + (PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW);
}

// UTF-8 to code points; false for bytes that are not UTF-8.
fn utf8_points(s: const u8[:], out: i64[>..]&) -> bool {
    var i = 0;
    while i < s.len {
        let c = s[i];
        var n = 0;
        var cp: i64 = 0;
        if c < 0x80 { cp = c; n = 1; }
        else if c >= 0xc2 && c < 0xe0 { cp = c & 0x1f; n = 2; }
        else if c >= 0xe0 && c < 0xf0 { cp = c & 0x0f; n = 3; }
        else if c >= 0xf0 && c < 0xf5 { cp = c & 0x07; n = 4; }
        else { return false; }
        if i + n > s.len { return false; }
        for k in 1..n {
            let d = s[i + k];
            if (d & 0xc0) != 0x80 { return false; }
            cp = (cp << 6) | (d & 0x3f);
        }
        if (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff) {
            return false;
        }
        out.push(cp);
        i += n;
    }
    return true;
}

// One label's Punycode (RFC 3492 §6.3), without the "xn--" prefix.
fn punycode_encode(out: u8[>..]&, label: const u8[:]) -> bool {
    var cps: i64[>..] = [];
    if !utf8_points(label, cps) { return false; }
    var n = PUNY_INITIAL_N;
    var delta: i64 = 0;
    var bias = PUNY_INITIAL_BIAS;
    var b: i64 = 0;
    for cp in cps { if cp < 0x80 { out.push(cp as! u8); b++; } }
    var h = b;
    if b > 0 { out.push('-'); }
    while h < cps.len {
        var m: i64 = 0x7fffffff;
        for cp in cps { if cp >= n && cp < m { m = cp; } }
        delta += (m - n) * (h + 1);
        if delta > 0x7fffffff { return false; }
        n = m;
        for cp in cps {
            if cp < n { delta++; }
            if cp == n {
                var q = delta;
                var k = PUNY_BASE;
                while true {
                    var t = k - bias;
                    if t < PUNY_TMIN { t = PUNY_TMIN; } else if t > PUNY_TMAX { t = PUNY_TMAX; }
                    if q < t { break; }
                    out.push(puny_digit(t + (q - t) % (PUNY_BASE - t)));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                out.push(puny_digit(q));
                bias = puny_adapt(delta, h + 1, h == b);
                delta = 0;
                h++;
            }
        }
        delta++;
        n++;
    }
    return true;
}

// A host name in ASCII: each label with a byte past 0x7f as "xn--" and its
// Punycode, ASCII letters lowered in such labels only (Go's cookiejar
// toASCII). Names already ASCII come back unchanged.
fn to_ascii_host(h: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var ascii = true;
    for c in h { if c >= 0x80 { ascii = false; } }
    if ascii { out.append(h); return out, true; }
    var ok = true;
    var first = true;
    each_split(h, '.') {
        if !first { out.push('.'); }
        first = false;
        var plain = true;
        for c in it { if c >= 0x80 { plain = false; } }
        if plain {
            out.append(it);
        } else {
            var low: u8[>..] = [];
            for c in it { low.push(lower(c)); }
            out.append("xn--");
            if !punycode_encode(out, low) { ok = false; }
        }
    };
    return out, ok;
}

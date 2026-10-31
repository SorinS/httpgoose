// http.cookie: HTTP cookies (RFC 6265): Set-Cookie fields parsed as a user
// agent does (§5.2, dates by §5.1.1), a cookie jar that keeps and sends
// them as Go's net/http/cookiejar does (§5.3, §5.4), the public suffix
// list that keeps a site from setting cookies for a whole registry
// (publicsuffix.org's format), and the cookie files of curl and Netscape.
//
//   var jar = http::new_jar();
//   http::jar_set_cookies(jar, psl, u, "id=7; Path=/; Max-Age=3600", now_ms);
//   var line: u8[>..] = [];
//   http::jar_cookie_header(jar, psl, u, now_ms, line);   // "id=7"
//
// Parsing follows RFC 6265 §5.2 where Go's ParseSetCookie is stricter:
// a name need not be a token and a value may have any byte but a control
// or ";" (Go refuses the cookie), Max-Age is "-" or a digit then digits
// (Go takes "+5" and refuses "05"), and Expires is §5.1.1's date (Go
// takes RFC 1123 and one other layout only). A cookie with neither a name
// nor a value is ignored (RFC 6265bis).
//
// Without a public suffix list (an empty Psl) the jar refuses a Domain
// attribute of one label, "com", unless it is the host itself; Go's jar
// without a list takes it, and so would let example.com set a cookie for
// all of .com.

namespace http;

import std;
import http;
import url;

// --- Set-Cookie (RFC 6265 §5.2) --------------------------------------------

let SAMESITE_UNSET: u8 = 0;
let SAMESITE_DEFAULT: u8 = 1;   // the attribute with a value that is none of these
let SAMESITE_LAX: u8 = 2;
let SAMESITE_STRICT: u8 = 3;
let SAMESITE_NONE: u8 = 4;

// A Set-Cookie field's cookie: spans into the field's value.
struct SetCookie {
    name: Span, value: Span,
    domain: Span, has_domain: bool,
    path: Span, has_path: bool,
    has_max_age: bool, max_age: i64,        // seconds; <= 0: expire now
    has_expires: bool, expires_ms: i64,     // Unix time in ms
    secure: bool, http_only: bool, same_site: u8, partitioned: bool,
}

fn is_ctl(c: u8) -> bool { c < 0x20 || c == 0x7f }

// The whitespace RFC 6265 trims: SP and HTAB.
fn cookie_trim(m: const u8[:], s: Span) -> Span {
    var a = s.pos;
    var b = s.end;
    while a < b && (m[a] == ' ' || m[a] == '\t') { a++; }
    while b > a && (m[b - 1] == ' ' || m[b - 1] == '\t') { b--; }
    return span(a, b);
}

fn fold_eq(m: const u8[:], s: Span, lit: const u8[:]) -> bool { eq_fold(m[s.pos..s.end], lit) }

// §5.2: the cookie of a Set-Cookie value, false to ignore the field. A
// value with a control byte other than HTAB is ignored whole (RFC 6265bis).
fn parse_set_cookie(m: const u8[:]) -> SetCookie, bool {
    var c = SetCookie {
        name: empty_span(), value: empty_span(), domain: empty_span(), has_domain: false,
        path: empty_span(), has_path: false, has_max_age: false, max_age: 0, has_expires: false, expires_ms: 0,
        secure: false, http_only: false, same_site: SAMESITE_UNSET, partitioned: false,
    };
    for ch in m { if is_ctl(ch) && ch != '\t' { return c, false; } }
    var semi = position(m, ';');
    if semi < 0 { semi = m.len; }
    let eq = position(m[..semi], '=');
    if eq < 0 {
        // RFC 6265bis §5.6 step 3: no "=": the whole is the value, the name empty.
        c.value = cookie_trim(m, span(0, semi));
    } else {
        c.name = cookie_trim(m, span(0, eq));
        c.value = cookie_trim(m, span(eq + 1, semi));
    }
    if span_len(c.name) == 0 && span_len(c.value) == 0 { return c, false; }
    var pos = semi;
    while pos < m.len {
        let start = pos + 1;
        var end = position(m[start..], ';');
        end = if end < 0 { m.len } else { start + end };
        pos = end;
        let av = span(start, end);
        let aeq = position(m[start..end], '=');
        var aname = av;
        var aval = empty_span();
        if aeq >= 0 {
            aname = span(start, start + aeq);
            aval = cookie_trim(m, span(start + aeq + 1, end));
        }
        aname = cookie_trim(m, aname);
        if fold_eq(m, aname, "expires") {
            let ms, ok = parse_cookie_date(m[aval.pos..aval.end]);
            if ok { c.has_expires = true; c.expires_ms = ms; }
        } else if fold_eq(m, aname, "max-age") {
            let v = m[aval.pos..aval.end];
            if v.len > 0 && ((v[0] >= '0' && v[0] <= '9') || v[0] == '-') {
                var ok = true;
                var n: i64 = 0;
                var neg = v[0] == '-';
                if neg && v.len == 1 { ok = false; }
                for i in (if neg { 1 } else { 0 })..v.len {
                    let d = v[i];
                    if d < '0' || d > '9' { ok = false; break; }
                    if n < 1000000000000 { n = n * 10 + (d - '0'); }
                }
                if ok {
                    c.has_max_age = true;
                    c.max_age = if neg { -n } else { n };
                }
            }
        } else if fold_eq(m, aname, "domain") {
            // §5.2.3: an empty value is ignored. The jar drops a leading
            // "." (domain_and_type).
            if span_len(aval) > 0 {
                c.has_domain = true;
                c.domain = aval;
            }
        } else if fold_eq(m, aname, "path") {
            // §5.2.4: a value not starting with "/" means the default path.
            if span_len(aval) > 0 && m[aval.pos] == '/' { c.has_path = true; c.path = aval; }
        } else if fold_eq(m, aname, "secure") {
            c.secure = true;
        } else if fold_eq(m, aname, "httponly") {
            c.http_only = true;
        } else if fold_eq(m, aname, "samesite") {
            let v = m[aval.pos..aval.end];
            c.same_site = if eq_fold(v, "lax") { SAMESITE_LAX } else if eq_fold(v, "strict") { SAMESITE_STRICT }
                          else if eq_fold(v, "none") { SAMESITE_NONE } else { SAMESITE_DEFAULT };
        } else if fold_eq(m, aname, "partitioned") {
            c.partitioned = true;
        }
    }
    return c, true;
}

// --- Dates (§5.1.1) --------------------------------------------------------

fn is_delimiter(c: u8) -> bool {
    c == 0x09 || (c >= 0x20 && c <= 0x2f) || (c >= 0x3b && c <= 0x40) || (c >= 0x5b && c <= 0x60) || (c >= 0x7b && c <= 0x7e)
}

fn is_digit(c: u8) -> bool { c >= '0' && c <= '9' }

// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn civil_from_days(z0: i64) -> i64, i64, i64 {
    let z = z0 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    return (if m <= 2 { y + 1 } else { y }), m, d;
}

let MONTHS: const u8[:] = "janfebmaraprmayjunjulaugsepoctnovdec";

// A cookie-date: Unix time in ms, false if it is not one.
fn parse_cookie_date(s: const u8[:]) -> i64, bool {
    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;
    var hh: i64 = 0; var mi: i64 = 0; var ss: i64 = 0;
    var dom: i64 = 0; var month: i64 = 0; var year: i64 = 0;
    var i = 0;
    while i < s.len {
        while i < s.len && is_delimiter(s[i]) { i++; }
        let start = i;
        while i < s.len && !is_delimiter(s[i]) { i++; }
        let tok = s[start..i];
        if tok.len == 0 { continue; }
        // time: 1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT ( non-digit *OCTET )
        if !found_time {
            var vals: i64[3] = [0; 3];
            var k = 0;
            var p = 0;
            var ok = true;
            while k < 3 {
                var n = 0;
                var v: i64 = 0;
                while p < tok.len && is_digit(tok[p]) && n < 3 { v = v * 10 + (tok[p] - '0'); p++; n++; }
                if n < 1 || n > 2 { ok = false; break; }
                vals[k] = v;
                k++;
                if k < 3 {
                    if p >= tok.len || tok[p] != ':' { ok = false; break; }
                    p++;
                }
            }
            if ok && (p == tok.len || !is_digit(tok[p])) {
                found_time = true;
                hh = vals[0]; mi = vals[1]; ss = vals[2];
                continue;
            }
        }
        // day-of-month: 1*2DIGIT ( non-digit *OCTET )
        if !found_dom {
            var p = 0;
            var v: i64 = 0;
            while p < tok.len && is_digit(tok[p]) && p < 3 { v = v * 10 + (tok[p] - '0'); p++; }
            if p >= 1 && p <= 2 && (p == tok.len || !is_digit(tok[p])) {
                found_dom = true;
                dom = v;
                continue;
            }
        }
        // month: the first three letters name one
        if !found_month && tok.len >= 3 {
            var mon = -1;
            for k in 12 {
                if eq_fold(tok[..3], MONTHS[k * 3..k * 3 + 3]) { mon = k + 1; }
            }
            if mon > 0 {
                found_month = true;
                month = mon;
                continue;
            }
        }
        // year: 2*4DIGIT ( non-digit *OCTET )
        if !found_year {
            var p = 0;
            var v: i64 = 0;
            while p < tok.len && is_digit(tok[p]) && p < 5 { v = v * 10 + (tok[p] - '0'); p++; }
            if p >= 2 && p <= 4 && (p == tok.len || !is_digit(tok[p])) {
                found_year = true;
                year = v;
                continue;
            }
        }
    }
    if found_year && year >= 70 && year <= 99 { year += 1900; }
    if found_year && year >= 0 && year <= 69 { year += 2000; }
    if !found_time || !found_dom || !found_month || !found_year { return 0, false; }
    if dom < 1 || dom > 31 || year < 1601 || hh > 23 || mi > 59 || ss > 59 { return 0, false; }
    // A day past the month's end is not a date.
    let days = days_from_civil(year, month, dom);
    let y2, m2, d2 = civil_from_days(days);
    if m2 != month { return 0, false; }
    return ((days * 86400) + hh * 3600 + mi * 60 + ss) * 1000, true;
}

// An HTTP date (IMF-fixdate, RFC 9110 §5.6.7) of Unix ms: "Sun, 06 Nov 1994 08:49:37 GMT".
fn format_http_date(out: u8[>..]&, ms: i64) {
    let secs = if ms >= 0 { ms / 1000 } else { -((-ms + 999) / 1000) };
    var days = secs / 86400;
    var rem = secs - days * 86400;
    if rem < 0 { rem += 86400; days--; }
    let y, m, d = civil_from_days(days);
    let wd = ((days % 7) + 11) % 7;             // 1970-01-01 was a Thursday
    out.append("SunMonTueWedThuFriSat"[wd * 3..wd * 3 + 3]);
    out.append(", ");
    format_int(out, d, 10, 2, '0');
    out.push(' ');
    var mon: u8[3] = [0; 3];
    for k in 3 { mon[k] = MONTHS[(m - 1) * 3 + k]; }
    mon[0] -= 32;
    out.append(mon);
    out.push(' ');
    format_int(out, y, 10, 4, '0');
    out.push(' ');
    format_int(out, rem / 3600, 10, 2, '0');
    out.push(':');
    format_int(out, (rem / 60) % 60, 10, 2, '0');
    out.push(':');
    format_int(out, rem % 60, 10, 2, '0');
    out.append(" GMT");
}

// --- The public suffix list ------------------------------------------------

// publicsuffix.org's rules, one a line ("com", "*.ck", "!www.ck"), kept as
// "\n" rule "\n" text (text_len bytes), then a hash table of `slots` u32
// entries, each 0 or one more than where a rule starts in the text, found
// by FNV-1a and linear probing; empty for none.
struct Psl { text_len: i64, slots: i64, rules: u8[>..] }

fn empty_psl() -> Psl { Psl { text_len: 0, slots: 0, rules: [] } }

fn psl_hash(rule: const u8[:]) -> u64 {
    var h: u64 = 0xcbf29ce484222325;
    for ch in rule { h = (h ^ ch) * 0x100000001b3; }
    return h;
}

fn psl_slot(p: const Psl&, k: i64) -> i64 {
    let at = p.text_len + k * 4;
    return (p.rules[at] as i64) | ((p.rules[at + 1] as i64) << 8) | ((p.rules[at + 2] as i64) << 16) | ((p.rules[at + 3] as i64) << 24);
}

// The table for the text: at least twice as many slots as rules.
fn psl_index(p: Psl&) {
    p.rules.resize(p.text_len);
    var count = 0;
    for ch in p.rules { if ch == '\n' { count++; } }
    var slots: i64 = 16;
    while slots < 2 * count { slots *= 2; }
    p.slots = slots;
    p.rules.resize(p.text_len + slots * 4, 0);
    var pos = 1;
    while pos < p.text_len {
        var end = pos;
        while p.rules[end] != '\n' { end++; }
        var k = (psl_hash(p.rules[pos..end]) & ((slots - 1) as! u64)) as! i64;
        while psl_slot(p, k) != 0 { k = (k + 1) & (slots - 1); }
        let v = pos + 1;
        for b in 4 { p.rules[p.text_len + k * 4 + b] = ((v >> (b * 8)) & 0xff) as! u8; }
        pos = end + 1;
    }
}

// Adds the rules of a list in publicsuffix.org's format: comments ("//")
// and blank lines skipped, each rule up to its first whitespace, lowered,
// non-ASCII labels in Punycode.
fn psl_load(p: Psl&, text: const u8[:]) -> i64 {
    var n = 0;
    p.rules.resize(p.text_len);
    if p.rules.len == 0 { p.rules.push('\n'); }
    each_split(text, '\n') {
        var line = it;
        var e = 0;
        while e < line.len && line[e] != ' ' && line[e] != '\t' && line[e] != '\r' { e++; }
        line = line[..e];
        if line.len > 0 && !starts_with(line, "//") {
            var excl = false;
            var body = line;
            if body[0] == '!' { excl = true; body = body[1..]; }
            var low: u8[>..] = [];
            for ch in body { low.push(lower(ch)); }
            let a, ok = to_ascii_host(low);
            if ok && a.len > 0 {
                if excl { p.rules.push('!'); }
                p.rules.append(a);
                p.rules.push('\n');
                n++;
            }
        }
    };
    p.text_len = p.rules.len;
    psl_index(p);
    return n;
}

// The list publicsuffix.org published on the date its VERSION line says
// (data/public_suffix_list.dat, MPL 2.0), built into the program.
fn psl_builtin(p: Psl&) -> i64 { psl_load(p, embed_file("data/public_suffix_list.dat")) }

// The registrable domain (the public suffix and one label more) of a
// host name, as publicsuffix.org's tests define it: false for a name that
// is a public suffix itself, starts with a dot, or has an empty label.
fn registrable_domain(p: const Psl&, name: const u8[:]) -> u8[>..], bool {
    var d: u8[>..] = [];
    if name.len == 0 || name[0] == '.' { return d, false; }
    var low: u8[>..] = [];
    for ch in name { low.push(lower(ch)); }
    let a, ok = to_ascii_host(low);
    if !ok || find(a, "..") >= 0 { return d, false; }
    let ps = public_suffix(p, a);
    if ps.len >= a.len { return d, false; }
    let rest = a[..a.len - ps.len - 1];
    let dot = last_index(rest, '.');
    d.append(a[dot + 1..]);
    return d, true;
}

fn psl_has(p: const Psl&, rule: const u8[:]) -> bool {
    if p.slots == 0 { return false; }
    var k = (psl_hash(rule) & ((p.slots - 1) as! u64)) as! i64;
    while true {
        let v = psl_slot(p, k);
        if v == 0 { return false; }
        let at = v - 1;
        if at + rule.len < p.text_len && p.rules[at + rule.len] == '\n' && p.rules[at..at + rule.len] == rule { return true; }
        k = (k + 1) & (p.slots - 1);
    }
    return false;
}

fn psl_empty(p: const Psl&) -> bool { p.text_len <= 1 }

// The public suffix of a lowercase ASCII domain by the list's algorithm:
// the longest matching rule, an exception rule winning and taking its
// leftmost label off; the rule "*" if none matches.
fn public_suffix(p: const Psl&, domain: const u8[:]) -> const u8[:] {
    // Each suffix of the domain, from the whole down to its last label.
    var best = -1;                  // where the longest match starts
    var starts: i64[>..] = [];
    starts.push(0);
    for i in domain.len { if domain[i] == '.' { starts.push(i + 1); } }
    var wild: u8[>..] = [];
    var excl: u8[>..] = [];
    for k in starts.len {
        let s = starts[k];
        let suffix = domain[s..];
        excl.clear();
        excl.push('!');
        excl.append(suffix);
        if psl_has(p, excl) {
            // The exception: the suffix without its leftmost label.
            let dot = position(suffix, '.');
            return if dot < 0 { suffix } else { domain[s + dot + 1..] };
        }
    }
    for k in starts.len {
        let s = starts[k];
        let suffix = domain[s..];
        if psl_has(p, suffix) { best = s; break; }
        // "*.rest" matches this suffix when its first label is any label.
        let dot = position(suffix, '.');
        if dot > 0 {
            wild.clear();
            wild.append("*.");
            wild.append(suffix[dot + 1..]);
            if psl_has(p, wild) { best = s; break; }
        }
    }
    if best < 0 {
        // The default rule "*": the last label.
        let last = last_index(domain, '.');
        return domain[last + 1..];
    }
    return domain[best..];
}

// --- The jar ---------------------------------------------------------------

// A jar: its cookies as records in `data`, each a header of numbers and
// then its name, value, domain, path and key (the registrable domain it is
// filed under, as Go's jarKey):
//
//   u32 record length, u8 flags, i64 expires_ms, i64 creation_ms, i64 seq,
//   u32 name, value, domain, path and key lengths, then their bytes
struct Jar { seq: i64, data: u8[>..] }

fn new_jar() -> Jar { Jar { seq: 0, data: [] } }

let CK_HOST_ONLY: u8 = 1;
let CK_SECURE: u8 = 2;
let CK_HTTP_ONLY: u8 = 4;
let CK_PERSISTENT: u8 = 8;
let CK_SAMESITE_SHIFT: u8 = 4;

let REC_HEADER: i64 = 4 + 1 + 8 + 8 + 8 + 4 * 5;
// Go's endOfTime: 9999-12-31 23:59:59 UTC, the expiry of a session cookie.
let END_OF_TIME_MS: i64 = 253402300799000;

fn put32(b: u8[>..]&, v: i64) { for k in 4 { b.push(((v >> (8 * k)) & 0xff) as! u8); } }
fn put64(b: u8[>..]&, v: i64) { for k in 8 { b.push(((v >> (8 * k)) & 0xff) as! u8); } }
fn get32(b: const u8[:], at: i64) -> i64 {
    var v: i64 = 0;
    for k in 4 { v |= (b[at + k] as i64) << (8 * k); }
    return v;
}
fn get64(b: const u8[:], at: i64) -> i64 {
    var v: u64 = 0;
    for k in 8 { v |= (b[at + k] as u64) << (8 * k); }
    return v as! i64;
}

// One record's parts.
struct CookieRec {
    pos: i64, len: i64, flags: u8, expires_ms: i64, creation_ms: i64, seq: i64,
    name: Span, value: Span, domain: Span, path: Span, key: Span,
}

fn rec_at(d: const u8[:], pos: i64) -> CookieRec {
    let len = get32(d, pos);
    var p = pos + REC_HEADER;
    var spans: Span[5] = [empty_span(); 5];
    for k in 5 {
        let n = get32(d, pos + 29 + 4 * k);
        spans[k] = span(p, p + n);
        p += n;
    }
    return CookieRec {
        pos: pos, len: len, flags: d[pos + 4], expires_ms: get64(d, pos + 5), creation_ms: get64(d, pos + 13),
        seq: get64(d, pos + 21), name: spans[0], value: spans[1], domain: spans[2], path: spans[3], key: spans[4],
    };
}

fn put_rec(out: u8[>..]&, flags: u8, expires_ms: i64, creation_ms: i64, seq: i64, name: const u8[:],
           value: const u8[:], domain: const u8[:], path: const u8[:], key: const u8[:]) {
    put32(out, REC_HEADER + name.len + value.len + domain.len + path.len + key.len);
    out.push(flags);
    put64(out, expires_ms);
    put64(out, creation_ms);
    put64(out, seq);
    put32(out, name.len); put32(out, value.len); put32(out, domain.len); put32(out, path.len); put32(out, key.len);
    out.append(name); out.append(value); out.append(domain); out.append(path); out.append(key);
}

fn jar_count(j: const Jar&) -> i64 {
    var n = 0;
    var pos = 0;
    while pos < j.data.len { n++; pos += get32(j.data, pos); }
    return n;
}

// Removes the record at pos.
fn jar_remove_at(j: Jar&, pos: i64) {
    let len = get32(j.data, pos);
    let rest = j.data.len - pos - len;
    for k in rest { j.data[pos + k] = j.data[pos + len + k]; }
    j.data.resize(j.data.len - len);
}

fn has_dot_suffix(s: const u8[:], suffix: const u8[:]) -> bool {
    return s.len > suffix.len && s[s.len - suffix.len - 1] == '.' && s[s.len - suffix.len..] == suffix;
}

// Go's canonicalHost on a URL's host field ("host", "host:port",
// "[v6]:port"): the port taken off, one trailing dot dropped, non-ASCII
// labels in Punycode, ASCII lowered.
fn canonical_host(hostport: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var h = hostport;
    var colons = 0;
    for ch in h { if ch == ':' { colons++; } }
    let has_port = colons == 1 || (colons > 1 && h.len > 0 && h[0] == '[' && find(h, "]:") >= 0);
    if has_port {
        // net.SplitHostPort: "[host]:port" or "host:port", no other bracket.
        if h[0] == '[' {
            let close = position(h, ']');
            if close < 0 || close + 1 >= h.len || h[close + 1] != ':' { return out, false; }
            if position(h[close + 1..], ']') >= 0 { return out, false; }
            h = h[1..close];
        } else {
            let colon = last_index(h, ':');
            if position(h[..colon], ':') >= 0 || position(h, '[') >= 0 || position(h, ']') >= 0 { return out, false; }
            h = h[..colon];
        }
    }
    if h.len > 0 && h[h.len - 1] == '.' { h = h[..h.len - 1]; }
    let a, ok = to_ascii_host(h);
    if !ok { return out, false; }
    for ch in a { out.push(lower(ch)); }
    return out, true;
}

// A URL's host as the jar files it: canonical_host of its decoded name (an
// IPv6 address without zone or brackets).
fn cookie_host(u: const Url&) -> u8[>..], bool {
    if u.ipv6 {
        let h, ok = url_ascii_host(u);
        var out: u8[>..] = [];
        for ch in h { out.push(lower(ch)); }
        return out, ok;
    }
    let h = url_hostname(u);
    return canonical_host(h);
}

// Go's isIP for the jar: anything with ":" or "%" (IPv6, a zone), or an
// IPv4 address.
fn cookie_is_ip(h: const u8[:]) -> bool {
    if position(h, ':') >= 0 || position(h, '%') >= 0 { return true; }
    let ip, kind = parse_ip(h);
    return kind == 4;
}

// Go's jarKey: the registrable domain (eTLD+1) a host's cookies are filed
// under; without a list, the last two labels.
fn jar_key(p: const Psl&, host: const u8[:]) -> const u8[:] {
    if cookie_is_ip(host) { return host; }
    var i: i64 = 0;
    if psl_empty(p) {
        i = last_index(host, '.');
        if i <= 0 { return host; }
    } else {
        let suffix = public_suffix(p, host);
        if suffix.len == host.len { return host; }
        i = host.len - suffix.len;
        if i <= 0 || host[i - 1] != '.' { return host; }
    }
    let prev = last_index(host[..i - 1], '.');
    return host[prev + 1..];
}

// Go's defaultPath (RFC 6265 §5.1.4).
fn default_cookie_path(path: const u8[:]) -> const u8[:] {
    if path.len == 0 || path[0] != '/' { return "/"; }
    let i = last_index(path, '/');
    if i == 0 { return "/"; }
    return path[..i];
}

// Go's domainAndType: the domain a cookie belongs to, and whether only the
// host itself gets it; false to refuse the cookie.
fn domain_and_type(p: const Psl&, host: const u8[:], domain0: const u8[:], has_domain: bool) -> u8[>..], bool, bool {
    var out: u8[>..] = [];
    if !has_domain || domain0.len == 0 { out.append(host); return out, true, true; }
    if cookie_is_ip(host) {
        // RFC 6265 is not clear about an IP's Domain attribute; Go takes
        // it only when it is the IP itself, as a host-only cookie.
        if host != domain0 { return out, false, false; }
        out.append(host);
        return out, true, true;
    }
    // §5.2.3 drops one leading "."; Go then refuses an empty domain ("Domain=.")
    // or one with another "." first.
    let domain = if domain0[0] == '.' { domain0[1..] } else { domain0 };
    if domain.len == 0 || domain[0] == '.' { return out, false, false; }
    for ch in domain { if ch < 0x20 || ch > 0x7e { return out, false, false; } }
    var d: u8[>..] = [];
    for ch in domain { d.push(lower(ch)); }
    if d[d.len - 1] == '.' { return out, false, false; }
    if !psl_empty(p) {
        let ps = public_suffix(p, d);
        if ps.len > 0 && !has_dot_suffix(d, ps) {
            // The domain is a public suffix: only its own host may have it,
            // and as a host-only cookie (RFC 6265 §5.3 step 5).
            if host == d[..] { out.append(host); return out, true, true; }
            return out, false, false;
        }
    } else if position(d, '.') < 0 && host != d[..] {
        // No list: no single-label domain but the host itself.
        return out, false, false;
    }
    if host != d[..] && !has_dot_suffix(host, d) { return out, false, false; }
    out.append(d);
    return out, false, true;
}

// The cookies of one Set-Cookie value, received from u at now_ms, into the
// jar (Go's SetCookies). False if the cookie was refused.
fn jar_set_cookie(j: Jar&, p: const Psl&, u: const Url&, line: const u8[:], now_ms: i64) -> bool {
    let sc = url_scheme(u);
    if sc != "http" && sc != "https" { return false; }
    let host, hok = cookie_host(u);
    if !hok { return false; }
    let c, ok = parse_set_cookie(line);
    if !ok { return false; }
    let key = jar_key(p, host);
    let path = if c.has_path { line[c.path.pos..c.path.end] } else { default_cookie_path(url_path(u)) };
    let domain, host_only, dok = domain_and_type(p, host, line[c.domain.pos..c.domain.end], c.has_domain);
    if !dok { return false; }
    let name = line[c.name.pos..c.name.end];
    // The record with the same name, domain and path, if there is one.
    var old = -1;
    var pos = 0;
    while pos < j.data.len {
        let r = rec_at(j.data, pos);
        if j.data[r.name.pos..r.name.end] == name && j.data[r.domain.pos..r.domain.end] == domain[..] &&
           j.data[r.path.pos..r.path.end] == path && j.data[r.key.pos..r.key.end] == key {
            old = pos;
            break;
        }
        pos += r.len;
    }
    var expires = END_OF_TIME_MS;
    var persistent = false;
    var remove = false;
    if c.has_max_age {
        if c.max_age <= 0 { remove = true; }
        else { expires = now_ms + c.max_age * 1000; persistent = true; }
    } else if c.has_expires {
        if c.expires_ms <= now_ms { remove = true; }
        else { expires = c.expires_ms; persistent = true; }
    }
    var creation = now_ms;
    var seq = j.seq;
    if old >= 0 {
        let r = rec_at(j.data, old);
        creation = r.creation_ms;
        seq = r.seq;
        jar_remove_at(j, old);
    } else if !remove {
        j.seq++;
    }
    if remove { return true; }
    var flags: u8 = 0;
    if host_only { flags |= CK_HOST_ONLY; }
    if c.secure { flags |= CK_SECURE; }
    if c.http_only { flags |= CK_HTTP_ONLY; }
    if persistent { flags |= CK_PERSISTENT; }
    flags |= c.same_site << CK_SAMESITE_SHIFT;
    var rec: u8[>..] = [];
    put_rec(rec, flags, expires, creation, seq, name, line[c.value.pos..c.value.end], domain, path, key);
    j.data.append(rec);
    return true;
}

fn is_localhost_domain(d: const u8[:]) -> bool {
    var h = d;
    if h.len > 0 && h[h.len - 1] == '.' { h = h[..h.len - 1]; }
    let i = last_index(h, '.');
    return eq_fold(h[i + 1..], "localhost");
}

fn cookie_path_match(req: const u8[:], cp: const u8[:]) -> bool {
    if req == cp { return true; }
    if starts_with(req, cp) {
        if cp.len > 0 && cp[cp.len - 1] == '/' { return true; }
        if req[cp.len] == '/' { return true; }
    }
    return false;
}

// Go's shouldSend: domain, path and Secure (which loopback hosts need not
// meet).
fn should_send(d: const u8[:], r: const CookieRec&, https: bool, host: const u8[:], path: const u8[:]) -> bool {
    let domain = d[r.domain.pos..r.domain.end];
    let dm = domain == host || ((r.flags & CK_HOST_ONLY) == 0 && has_dot_suffix(host, domain));
    if !dm || !cookie_path_match(path, d[r.path.pos..r.path.end]) { return false; }
    if (r.flags & CK_SECURE) == 0 || https { return true; }
    if is_localhost_domain(domain) { return true; }
    let ip, kind = parse_ip(domain);
    return ip_is_loopback(ip, kind);
}

// The cookies to send to u at now_ms, in Go's order (by path, longest
// first, then oldest first), as F(name, value). Expired ones are dropped.
fn jar_cookies<F>(j: Jar&, p: const Psl&, u: const Url&, now_ms: i64) {
    let sc = url_scheme(u);
    if sc != "http" && sc != "https" { return; }
    let host, hok = cookie_host(u);
    if !hok { return; }
    let key = jar_key(p, host);
    let https = sc == "https";
    let path = if span_len(u.path) == 0 { "/" } else { url_path(u) };
    // Drop what has expired.
    var pos = 0;
    while pos < j.data.len {
        let r = rec_at(j.data, pos);
        if j.data[r.key.pos..r.key.end] == key && (r.flags & CK_PERSISTENT) != 0 && r.expires_ms <= now_ms {
            jar_remove_at(j, pos);
            continue;
        }
        pos += r.len;
    }
    var picked: i64[>..] = [];
    pos = 0;
    while pos < j.data.len {
        let r = rec_at(j.data, pos);
        if j.data[r.key.pos..r.key.end] == key && should_send(j.data, r, https, host, path) { picked.push(pos); }
        pos += r.len;
    }
    // Go sorts by path (descending, as strings), then creation, then sequence.
    let d = j.data[..];
    stable_sort(picked) { a, b => cookie_before(d, a, b) };
    for at in picked {
        let r = rec_at(j.data, at);
        F(j.data[r.name.pos..r.name.end], j.data[r.value.pos..r.value.end]);
    }
}

fn cookie_before(d: const u8[:], a: i64, b: i64) -> bool {
    let ra = rec_at(d, a);
    let rb = rec_at(d, b);
    let c = compare(d[rb.path.pos..rb.path.end], d[ra.path.pos..ra.path.end]);
    if c != 0 { return c < 0; }
    if ra.creation_ms != rb.creation_ms { return ra.creation_ms < rb.creation_ms; }
    return ra.seq < rb.seq;
}

// The Cookie field's value for u: "a=1; b=2" (RFC 6265 §5.4); false if
// there are none.
fn jar_cookie_header(j: Jar&, p: const Psl&, u: const Url&, now_ms: i64, out: u8[>..]&) -> bool {
    var any = false;
    jar_cookies(j, p, u, now_ms) { name, value =>
        if any { out.append("; "); }
        out.append(name);
        if name.len > 0 { out.push('='); }
        out.append(value);
        any = true;
    };
    return any;
}

// --- Cookie files ----------------------------------------------------------

// curl's and Netscape's cookies.txt: one cookie a line, tab-separated:
// domain, "TRUE" if subdomains get it (the domain then starts with "."),
// path, "TRUE" if Secure, expiry in Unix seconds (0: a session cookie),
// name, value. "#HttpOnly_" before the domain marks HttpOnly; other lines
// starting with "#" are comments. Cookies past now_ms are skipped; the
// key is worked out from the domain.
fn jar_load_netscape(j: Jar&, p: const Psl&, text: const u8[:], now_ms: i64) -> i64 {
    var n = 0;
    each_split(text, '\n') {
        var line = it;
        if line.len > 0 && line[line.len - 1] == '\r' { line = line[..line.len - 1]; }
        var http_only = false;
        if starts_with(line, "#HttpOnly_") { http_only = true; line = line[10..]; }
        if line.len > 0 && line[0] != '#' {
            let parts = split(line, '\t');
            if parts.len == 7 {
                var domain = parts[0];
                let sub = parts[1] == "TRUE";
                if domain.len > 0 && domain[0] == '.' { domain = domain[1..]; }
                let exp_s, eok = parse_int(parts[4]);
                if eok && domain.len > 0 {
                    var flags: u8 = 0;
                    if !sub { flags |= CK_HOST_ONLY; }
                    if parts[3] == "TRUE" { flags |= CK_SECURE; }
                    if http_only { flags |= CK_HTTP_ONLY; }
                    var expires = END_OF_TIME_MS;
                    if exp_s > 0 { flags |= CK_PERSISTENT; expires = exp_s * 1000; }
                    if exp_s <= 0 || expires > now_ms {
                        var low: u8[>..] = [];
                        for ch in domain { low.push(lower(ch)); }
                        let key = jar_key(p, low);
                        var rec: u8[>..] = [];
                        put_rec(rec, flags, expires, now_ms, j.seq, parts[5], parts[6], low, parts[2], key);
                        j.seq++;
                        j.data.append(rec);
                        n++;
                    }
                }
            }
        }
    };
    return n;
}

// The jar in that format: persistent cookies, and with `sessions` the
// session ones too (with expiry 0), as curl writes them.
fn jar_save_netscape(j: const Jar&, out: u8[>..]&, now_ms: i64, sessions: bool) {
    out.append("# Netscape HTTP Cookie File\n# This file was generated by goose http.cookie. Edit at your own risk.\n\n");
    var pos = 0;
    while pos < j.data.len {
        let r = rec_at(j.data, pos);
        pos += r.len;
        let persistent = (r.flags & CK_PERSISTENT) != 0;
        if (persistent && r.expires_ms <= now_ms) || (!persistent && !sessions) { continue; }
        if (r.flags & CK_HTTP_ONLY) != 0 { out.append("#HttpOnly_"); }
        let sub = (r.flags & CK_HOST_ONLY) == 0;
        if sub { out.push('.'); }
        out.append(j.data[r.domain.pos..r.domain.end]);
        out.append(if sub { "\tTRUE\t" } else { "\tFALSE\t" });
        out.append(j.data[r.path.pos..r.path.end]);
        out.append(if (r.flags & CK_SECURE) != 0 { "\tTRUE\t" } else { "\tFALSE\t" });
        format(out, if persistent { r.expires_ms / 1000 } else { 0 });
        out.push('\t');
        out.append(j.data[r.name.pos..r.name.end]);
        out.push('\t');
        out.append(j.data[r.value.pos..r.value.end]);
        out.push('\n');
    }
}

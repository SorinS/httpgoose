// http.cookie: Go's own cookie jar tests (test/vectors/cookiejar*.txt from
// scripts/gen_cookie_vectors.py, run as Go runs them: the jar's public
// suffix list is testPSL's, "co.uk" and the default rule), Set-Cookie
// parsing by RFC 6265 §5.2, cookie dates (§5.1.1), the public suffix
// algorithm, and cookie files.

import std;
import http from "..";
import http.url;
import http.cookie;

var failures = 0;

fn check(what: const u8[:], got: const u8[:], want: const u8[:]) {
    if got != want {
        print("FAIL ", what, ":\n  got  '", got, "'\n  want '", want, "'");
        failures++;
    }
}

fn check_bool(what: const u8[:], got: bool, want: bool) {
    if got != want { print("FAIL ", what, ": got ", got); failures++; }
}

fn unesc(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        if s[i] == '\\' && i + 1 < s.len {
            let c = s[i + 1];
            out.push(if c == 't' { '\t' } else if c == 'n' { '\n' } else { c });
            i += 2;
        } else {
            out.push(s[i]);
            i++;
        }
    }
    return out;
}

// Go's Cookie.String() of a name and value from the jar: quoted if it has
// a space or a comma.
fn go_cookie(out: u8[>..]&, name: const u8[:], value: const u8[:]) {
    out.append(name);
    out.push('=');
    let quoted = value.len >= 2 && value[0] == '"' && value[value.len - 1] == '"';
    let needs = position(value, ' ') >= 0 || position(value, ',') >= 0;
    if needs && !quoted { out.push('"'); out.append(value); out.push('"'); } else { out.append(value); }
}

let T0: i64 = 1357041600000;    // Go's tNow: 2013-01-01 12:00:00 UTC

// The jar's content at now, as Go's test writes it: "name=value" sorted.
fn content(j: const http::Jar&, now: i64) -> u8[>..] {
    var all: u8[>..] = [];
    var pos = 0;
    while pos < j.data.len {
        let r = http::rec_at(j.data, pos);
        pos += r.len;
        if r.expires_ms <= now { continue; }
        go_cookie(all, j.data[r.name.pos..r.name.end], j.data[r.value.pos..r.value.end]);
        all.push('\n');
    }
    var items = split(all, '\n');
    sort(items) { a, b => compare(a, b) < 0 };
    var out: u8[>..] = [];
    for it in items {
        if it.len == 0 { continue; }
        if out.len > 0 { out.push(' '); }
        out.append(it);
    }
    return out;
}

fn query(j: http::Jar&, p: const http::Psl&, us: const u8[:], now: i64) -> u8[>..] {
    var out: u8[>..] = [];
    let u, e = http::url_parse(us);
    if e != 0 { return out; }
    http::jar_cookies(j, p, u, now) { name, value =>
        if out.len > 0 { out.push(' '); }
        go_cookie(out, name, value);
    };
    return out;
}

// Where this package follows RFC 6265 and Go does not: §5.2 step 4 trims
// whitespace off a cookie's value as well as its name, so "cookie-4= ,"
// keeps ",", where Go's ParseSetCookie keeps " ,".
fn rfc_want(desc: const u8[:], want: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let from = "cookie-4=\" ,\"";
    let at = find(want, from);
    if desc == "Retrieval of cookies with quoted values" && at >= 0 {
        out.append(want[..at]);
        out.append("cookie-4=\",\"");
        out.append(want[at + from.len..]);
        return out;
    }
    out.append(want);
    return out;
}

fn jar_vectors(p: const http::Psl&) {
    let data = embed_file("vectors/cookiejar.txt");
    var j = http::new_jar();
    var fresh = true;
    var desc: u8[>..] = [];
    var from: u8[>..] = [];
    var sets: u8[>..] = [];         // NUL-separated
    var want_content: u8[>..] = [];
    var queries: u8[>..] = [];      // url TAB want NUL ...
    var tests = 0;
    each_split(data, '\n') {
        let line = it;
        let tab = position(line, '\t');
        let tag = if tab < 0 { line } else { line[..tab] };
        let rest = if tab < 0 { "" } else { line[tab + 1..] };
        if tag == "group" {
            let t2 = position(rest, '\t');
            fresh = rest[t2 + 1..] == "fresh";
            j = http::new_jar();
        } else if tag == "test" {
            desc.clear(); desc.append(unesc(rest));
            sets.clear(); queries.clear(); want_content.clear(); from.clear();
        } else if tag == "from" {
            from.append(unesc(rest));
        } else if tag == "set" {
            sets.append(unesc(rest)); sets.push(0);
        } else if tag == "content" {
            want_content.append(unesc(rest));
        } else if tag == "query" {
            queries.append(rest); queries.push(0);
        } else if tag == "end" {
            tests++;
            if fresh { j = http::new_jar(); }
            let u, e = http::url_parse(from);
            check_bool("from URL", e == 0, true);
            var now = T0;
            each_split(sets, 0) { if it.len > 0 { http::jar_set_cookie(j, p, u, it, now); } };
            now += 1001;
            var what: u8[>..] = [];
            what.append(desc); what.append(" (content)");
            check(what, content(j, now), rfc_want(desc, want_content));
            var qn = 0;
            each_split(queries, 0) {
                if it.len > 0 {
                    now += 1001;
                    let t = position(it, '\t');
                    let qurl = unesc(it[..t]);
                    let want = unesc(it[t + 1..]);
                    var w: u8[>..] = [];
                    w.append(desc); w.append(" #"); format(w, qn); w.append(" "); w.append(qurl);
                    check(w, query(j, p, qurl, now), rfc_want(desc, want));
                    qn++;
                }
            };
        }
    };
    print("jar tests: ", tests);
}

fn unit_vectors(p: const http::Psl&, none: const http::Psl&) {
    let data = embed_file("vectors/cookiejar_units.txt");
    var n = 0;
    each_split(data, '\n') {
        let line = it;
        if line.len > 0 && line[0] != '#' {
            let f = split(line, '\t');
            let tag = f[0];
            let a = unesc(f[1]);
            n++;
            if tag == "jarKey" {
                // testPSL's two deliberate bugs (www.buggy.psl's suffix "xy",
                // www2.buggy.psl's "com") check that Go's jar survives a broken
                // list; a list read from rules cannot be broken that way.
                if a[..] != "www.buggy.psl" && a[..] != "www2.buggy.psl" { check(line, http::jar_key(p, a), unesc(f[2])); }
            } else if tag == "jarKeyNilPSL" {
                check(line, http::jar_key(none, a), unesc(f[2]));
            } else if tag == "defaultPath" {
                check(line, http::default_cookie_path(a), unesc(f[2]));
            } else if tag == "isIP" {
                check_bool(line, http::cookie_is_ip(a), f[2] == "true");
            } else if tag == "canonicalHost" {
                let h, ok = http::canonical_host(a);
                if f[2] == "error" { check_bool(line, ok, false); } else { check_bool(line, ok, true); check(line, h, unesc(f[2])); }
            } else if tag == "hasDotSuffix" {
                check_bool(line, http::has_dot_suffix(a, unesc(f[2])), f[3] == "true");
            } else if tag == "domainAndType" {
                let d, host_only, ok = http::domain_and_type(p, a, unesc(f[2]), true);
                let want_ok = f[5] == "true";
                check_bool(line, ok, want_ok);
                if want_ok {
                    check(line, d, unesc(f[3]));
                    check_bool(line, host_only, f[4] == "true");
                }
            }
        }
    };
    print("unit vectors: ", n);
}

fn sc(line: const u8[:]) -> http::SetCookie {
    let c, ok = http::parse_set_cookie(line);
    if !ok { print("FAIL parse ", line); failures++; }
    return c;
}

fn parsing() {
    let l1 = "  id = a b ; Path=/x ; Domain=.Example.COM; Secure; HttpOnly; SameSite=Lax; Max-Age=60; Partitioned";
    let c = sc(l1);
    check("name", l1[c.name.pos..c.name.end], "id");
    check("value", l1[c.value.pos..c.value.end], "a b");
    check("path", l1[c.path.pos..c.path.end], "/x");
    check("domain", l1[c.domain.pos..c.domain.end], ".Example.COM");
    check_bool("secure", c.secure, true);
    check_bool("httponly", c.http_only, true);
    check_bool("samesite", c.same_site == http::SAMESITE_LAX, true);
    check_bool("max-age", c.has_max_age && c.max_age == 60, true);
    check_bool("partitioned", c.partitioned, true);
    // §5.2: a later attribute of a name wins; no "=": a value, the name empty.
    let l2 = "x=1; path=/a; Path=/b; max-age=5; max-age=-1";
    let c2 = sc(l2);
    check("last path", l2[c2.path.pos..c2.path.end], "/b");
    check_bool("last max-age", c2.max_age == -1, true);
    let l3 = "justvalue";
    let c3 = sc(l3);
    check("no name", l3[c3.name.pos..c3.name.end], "");
    check("value only", l3[c3.value.pos..c3.value.end], "justvalue");
    let e1, k1 = http::parse_set_cookie("=");
    check_bool("empty name and value", k1, false);
    let e2, k2 = http::parse_set_cookie("a=b\x01");
    check_bool("control", k2, false);
    let e3, k3 = http::parse_set_cookie("a=b\tc");
    check_bool("tab", k3, true);
    // Max-Age: "-" or a digit first, then digits; others are ignored.
    let c4 = sc("a=1; Max-Age=+5");
    check_bool("max-age +5 ignored", c4.has_max_age, false);
    let c5 = sc("a=1; Max-Age=007");
    check_bool("max-age 007", c5.has_max_age && c5.max_age == 7, true);
    let c6 = sc("a=1; Max-Age=5x");
    check_bool("max-age 5x", c6.has_max_age, false);
    let c7 = sc("a=1; Path=relative");
    check_bool("relative path ignored", c7.has_path, false);
    let c8 = sc("a=1; Domain=");
    check_bool("empty domain ignored", c8.has_domain, false);
    let c9 = sc("a=1; SameSite=bogus");
    check_bool("samesite other", c9.same_site == http::SAMESITE_DEFAULT, true);
    let c10 = sc("a=\"q v\"; expires=Wed, 09 Jun 2021 10:18:14 GMT");
    check_bool("expires", c10.has_expires && c10.expires_ms == 1623233894000, true);
}

let NOT_A_DATE: i64 = -999;

fn date(s: const u8[:], want_ms: i64) {
    let ms, ok = http::parse_cookie_date(s);
    if want_ms == NOT_A_DATE { check_bool(s, ok, false); return; }
    check_bool(s, ok, true);
    if ok && ms != want_ms { print("FAIL date ", s, ": got ", ms); failures++; }
}

fn dates() {
    // 2021-06-09 10:18:14 UTC in the layouts servers send.
    let t: i64 = 1623233894000;
    date("Wed, 09 Jun 2021 10:18:14 GMT", t);
    date("Wed, 09-Jun-2021 10:18:14 GMT", t);
    date("Wednesday, 09-Jun-21 10:18:14 GMT", t);
    date("Wed Jun  9 10:18:14 2021", t);
    date("9 jun 2021 10:18:14", t);
    date("Wed, 09 Jun 2021 10:18:14 UTC", t);
    date("Wed, 09 Jun 2021 10:18:14 +0000", t);
    date("Thu, 01 Jan 1970 00:00:00 GMT", 0);
    date("Thu, 01 Jan 70 00:00:00 GMT", 0);
    date("Sat, 01 Jan 2000 00:00:00 GMT", 946684800000);
    date("Fri, 31 Dec 9999 23:59:59 GMT", 253402300799000);
    date("Mon, 01 Jan 1601 00:00:00 GMT", -11644473600000);
    date("Sun, 31 Dec 1600 23:59:59 GMT", NOT_A_DATE);   // before 1601
    date("Wed, 31 Jun 2021 10:18:14 GMT", NOT_A_DATE);   // no 31 June
    date("Wed, 09 Jun 2021 24:00:00 GMT", NOT_A_DATE);
    date("Wed, 09 Jun 2021 10:60:00 GMT", NOT_A_DATE);
    date("Wed, 09 Jun 2021", NOT_A_DATE);                // no time
    date("Wed, Jun 2021 10:18:14 GMT", NOT_A_DATE);      // no day
    date("Wed, 09 2021 10:18:14 GMT", NOT_A_DATE);       // no month
    date("Wed, 09 Jun 10:18:14 GMT", NOT_A_DATE);        // no year
    date("Wed, 09 Jun 12021 10:18:14 GMT", NOT_A_DATE);
    date("", NOT_A_DATE);
    var out: u8[>..] = [];
    http::format_http_date(out, 784111777000);
    check("http date", out, "Sun, 06 Nov 1994 08:49:37 GMT");
    out.clear();
    http::format_http_date(out, 0);
    check("epoch", out, "Thu, 01 Jan 1970 00:00:00 GMT");
}

fn suffix(p: const http::Psl&, d: const u8[:], want: const u8[:]) {
    check(d, http::public_suffix(p, d), want);
}

fn psl() {
    var p = http::empty_psl();
    let n = http::psl_load(p, "// comment\ncom\nuk\nco.uk\n*.ck\n!www.ck\n*.kawasaki.jp\n!city.kawasaki.jp\n\xc3\xa9x.example  trailing\n\n");
    check_bool("rules", n == 8, true);
    suffix(p, "example.com", "com");
    suffix(p, "a.b.example.com", "com");
    suffix(p, "com", "com");
    suffix(p, "example.co.uk", "co.uk");
    suffix(p, "x.ck", "x.ck");
    suffix(p, "a.x.ck", "x.ck");
    suffix(p, "www.ck", "ck");
    suffix(p, "a.www.ck", "ck");
    suffix(p, "a.b.kawasaki.jp", "b.kawasaki.jp");
    suffix(p, "city.kawasaki.jp", "kawasaki.jp");
    suffix(p, "a.city.kawasaki.jp", "kawasaki.jp");
    suffix(p, "example.unknown", "unknown");     // the default rule "*"
    suffix(p, "a.xn--x-9fa.example", "xn--x-9fa.example");
    var j = http::new_jar();
    let u, e = http::url_parse("http://www.example.co.uk/");
    check_bool("supercookie refused", http::jar_set_cookie(j, p, u, "a=1; Domain=co.uk", T0), false);
    check_bool("site cookie taken", http::jar_set_cookie(j, p, u, "b=2; Domain=example.co.uk", T0), true);
    let none = http::empty_psl();
    let u2, e2 = http::url_parse("http://example.com/");
    check_bool("no list: TLD refused", http::jar_set_cookie(j, none, u2, "c=3; Domain=com", T0), false);
    check_bool("no list: own host", http::jar_set_cookie(j, none, u2, "d=4; Domain=example.com", T0), true);
    let u3, e3 = http::url_parse("http://localhost/");
    check_bool("no list: localhost itself", http::jar_set_cookie(j, none, u3, "e=5; Domain=localhost", T0), true);
}

// publicsuffix.org's tests/test_psl.txt against the built-in list:
// checkPublicSuffix('name', 'registrable domain' or null).
fn psl_official() {
    var p = http::empty_psl();
    let rules = http::psl_builtin(p);
    let data = embed_file("vectors/test_psl.txt");
    var n = 0;
    each_split(data, '\n') {
        let line = it;
        if starts_with(line, "checkPublicSuffix(") {
            let args = line[18..];
            var vals: u8[>..] = [];      // the two arguments, NUL-separated, "\x01" for null
            var i = 0;
            var k = 0;
            while i < args.len && k < 2 {
                if args[i] == '\'' {
                    let close = position(args[i + 1..], '\'');
                    vals.append(args[i + 1..i + 1 + close]);
                    vals.push(0);
                    i += close + 2;
                    k++;
                } else if starts_with(args[i..], "null") {
                    vals.push(1);
                    vals.push(0);
                    i += 4;
                    k++;
                } else {
                    i++;
                }
            }
            let parts = split(vals, 0);
            let input = parts[0];
            let want = parts[1];
            if input != "\x01" {
                n++;
                let got, ok = http::registrable_domain(p, input);
                if want == "\x01" {
                    if ok { print("FAIL psl ", input, ": got ", got, ", want null"); failures++; }
                } else {
                    var wl: u8[>..] = [];
                    for ch in want { wl.push(http::lower(ch)); }
                    let wa, wok = http::to_ascii_host(wl);
                    if !ok || got[..] != wa[..] { print("FAIL psl ", input, ": got ", got, " ok ", ok, ", want ", wa); failures++; }
                }
            }
        }
    };
    print("public suffix list rules: ", if rules > 9000 { "over 9000" } else { "too few" }, "; test_psl.txt checks: ", n);
}

fn files() {
    let none = http::empty_psl();
    var j = http::new_jar();
    let u, e = http::url_parse("https://www.example.com/a/b");
    http::jar_set_cookie(j, none, u, "s=1", T0);
    http::jar_set_cookie(j, none, u, "p=2; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly", T0);
    http::jar_set_cookie(j, none, u, "q=3; Expires=Wed, 09 Jun 2100 10:18:14 GMT", T0);
    var text: u8[>..] = [];
    http::jar_save_netscape(j, text, T0, true);
    var want: u8[>..] = [];
    want.append("# Netscape HTTP Cookie File\n# This file was generated by goose http.cookie. Edit at your own risk.\n\n");
    want.append("www.example.com\tFALSE\t/a\tFALSE\t0\ts\t1\n");
    want.append("#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1357045200\tp\t2\n");
    want.append("www.example.com\tFALSE\t/a\tFALSE\t4116219494\tq\t3\n");
    check("netscape", text, want);
    var k = http::new_jar();
    let n = http::jar_load_netscape(k, none, text, T0);
    check_bool("loaded 3", n == 3, true);
    var line: u8[>..] = [];
    http::jar_cookie_header(k, none, u, T0, line);
    check("loaded cookies", line, "s=1; q=3; p=2");
    var later: u8[>..] = [];
    http::jar_cookie_header(k, none, u, T0 + 3600000, later);
    check("p expired", later, "s=1; q=3");
    var plain: u8[>..] = [];
    let u2, e2 = http::url_parse("http://www.example.com/a/b");
    http::jar_cookie_header(k, none, u2, T0, plain);
    check("secure not on http", plain, "s=1; q=3");
    var text2: u8[>..] = [];
    http::jar_save_netscape(k, text2, T0 + 3600000, false);
    check_bool("sessions left out", find(text2, "\ts\t1") < 0, true);
}

fn main() {
    var p = http::empty_psl();
    http::psl_load(p, "co.uk\n");
    let none = http::empty_psl();
    jar_vectors(p);
    unit_vectors(p, none);
    parsing();
    dates();
    psl();
    psl_official();
    files();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("cookie: all passed");
}

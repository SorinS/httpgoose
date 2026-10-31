// http.client and http.fetch without the network: proxy selection against
// golang.org/x/net/http/httpproxy's own tables (test/vectors/proxy.txt from
// scripts/gen_proxy_vectors.py: the answers that package gives), and the
// redirect policy's field handling, and the TLS session cache's order of
// eviction. scripts/interop.py runs the rest against real servers.

import std;
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls from "../../tlsgoose.git";
import tls.session;
import http from "..";
import http.url;
import http.cookie;
import http.client;
import http.fetch;

var failures = 0;

fn check(what: const u8[:], got: const u8[:], want: const u8[:]) {
    if got != want {
        print("FAIL ", what, ":\n  got  '", got, "'\n  want '", want, "'");
        failures++;
    }
}

fn unesc(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
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

fn proxy_answer(c: http::Client&, url_text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let u, e = http::url_parse(url_text);
    if e != 0 { out.append("bad URL"); return out; }
    let p = http::proxy_for(c, u);
    if p.len == 0 { out.push('-'); } else { out.append(p); }
    return out;
}

fn proxy_vectors() {
    let data = embed_file("vectors/proxy.txt");
    var c = http::Client { .. };
    var n = 0;
    each_split(data, '\n') {
        let line = it;
        if line.len > 0 && line[0] != '#' {
            let f = split(line, '\t');
            n++;
            if f[0] == "proxy" {
                c.proxy_mode = http::PROXY_ENV;
                c.proxy_http.clear(); c.proxy_http.append(unesc(f[1]));
                c.proxy_https.clear(); c.proxy_https.append(unesc(f[2]));
                c.no_proxy.clear(); c.no_proxy.append(unesc(f[3]));
                c.proxy_cgi = f[4] == "1";
                var want: u8[>..] = [];
                if f[6] == "-" { want.push('-'); } else { want.append(unesc(f[6])); }
                // In a CGI program Go refuses an http request that HTTP_PROXY
                // would send through a proxy; this package sends it directly.
                if want[..] == "err" { want.clear(); want.push('-'); }
                check(line, proxy_answer(c, unesc(f[5])), want);
            } else if f[0] == "use" {
                c.proxy_mode = http::PROXY_ENV;
                c.proxy_http.clear(); c.proxy_http.append("http://proxy.test");
                c.proxy_https.clear();
                c.no_proxy.clear(); c.no_proxy.append(unesc(f[1]));
                c.proxy_cgi = false;
                var us: u8[>..] = [];
                us.append("http://");
                us.append(unesc(f[2]));
                us.append("/");
                let got = proxy_answer(c, us);
                let used = got[..] != "-";
                if used != (f[3] == "true") { print("FAIL ", line, ": used ", used); failures++; }
            }
        }
    };
    print("proxy vectors: ", n);
}

fn explicit_proxy() {
    var c = http::Client { .. };
    if !http::set_proxy(c, "http://u:p@proxy.test:3128", "") { print("FAIL set_proxy"); failures++; }
    // One proxy for all, loopback included (Go's ProxyURL; curl's -x).
    check("loopback through -x", proxy_answer(c, "http://127.0.0.1/"), "http://u:p@proxy.test:3128");
    check("https through -x", proxy_answer(c, "https://example.com/"), "http://u:p@proxy.test:3128");
    http::set_proxy(c, "socks5h://127.0.0.1:1080", "internal.test, 10.0.0.0/8");
    check("noproxy host", proxy_answer(c, "http://a.internal.test/"), "-");
    check("noproxy cidr", proxy_answer(c, "http://10.1.2.3/"), "-");
    check("other host", proxy_answer(c, "http://example.com/"), "socks5h://127.0.0.1:1080");
    if http::set_proxy(c, "ftp://x/", "") { print("FAIL ftp proxy taken"); failures++; }
    http::set_proxy(c, "", "");
    check("none", proxy_answer(c, "http://example.com/"), "-");
}

fn redirects() {
    let f = "Authorization: Basic x\r\nCookie: a=1\r\nContent-Type: text/plain\r\nX-Other: y\r\nProxy-Authorization: z\r\n";
    check("copy all", http::copy_fields(f, false, false), f);
    check("strip sensitive", http::copy_fields(f, true, false), "Content-Type: text/plain\r\nX-Other: y\r\n");
    check("strip body", http::copy_fields(f, false, true), "Authorization: Basic x\r\nCookie: a=1\r\nX-Other: y\r\nProxy-Authorization: z\r\n");
    let a, e1 = http::url_parse("http://example.com/");
    let pairs = [
        "http://example.com:8080/", "1", "https://example.com/", "1", "http://sub.example.com/", "1",
        "http://EXAMPLE.com./", "1", "http://example.org/", "0", "http://notexample.com/", "0",
        "http://com/", "0", "http://[::1]/", "0",
    ];
    var k = 0;
    while k < pairs.len {
        let b, e2 = http::url_parse(pairs[k]);
        let same = http::same_site_for_credentials(a, b);
        if same != (pairs[k + 1] == "1") { print("FAIL same site ", pairs[k], ": ", same); failures++; }
        k += 2;
    }
    var r: u8[>..] = [];
    let u, e3 = http::url_parse("https://user:pw@example.com/a?b#c");
    check("referer", http::url_referer(u), "https://example.com/a?b");
}

fn a_session(id: u8) -> tls::Session {
    var s = tls::no_session();
    s.suite = tls::TLS_AES_128_GCM_SHA256;
    for k in 32 { s.psk.push(id); }
    s.ticket.append("ticket ");
    s.ticket.push(id);
    s.lifetime = 3600;
    return s;
}

fn put(c: http::Client&, name: const u8[:], id: u8) {
    let s = a_session(id);
    http::session_put(c, name, s);
}

fn cached(c: http::Client&, name: const u8[:]) -> u8[>..] {
    let s, ok = http::session_get(c, name);
    var out: u8[>..] = [];
    if ok { out.append(s.ticket); } else { out.append("-"); }
    return out;
}

// Go's lruSessionCache: the least recently used goes; a get counts as a use.
fn session_cache() {
    var c = http::Client { .. };
    c.opt.tls_sessions = 2;
    put(c, "a", 'a');
    put(c, "b", 'b');
    put(c, "c", 'c');
    check("lru: a went", cached(c, "a"), "-");
    check("lru: b kept", cached(c, "b"), "ticket b");
    put(c, "d", 'd');      // c is older than b now
    check("lru: c went", cached(c, "c"), "-");
    check("lru: b still", cached(c, "b"), "ticket b");
    check("lru: d", cached(c, "d"), "ticket d");
    put(c, "b", 'B');      // replaced, not added
    check("lru: b replaced", cached(c, "b"), "ticket B");
    check("lru: d kept", cached(c, "d"), "ticket d");
    http::session_drop(c, "b");
    check("lru: b dropped", cached(c, "b"), "-");
    var off = http::Client { .. };
    off.opt.tls_sessions = 0;
    put(off, "a", 'a');
    check("no cache", cached(off, "a"), "-");
}

fn main() {
    session_cache();
    proxy_vectors();
    explicit_proxy();
    redirects();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("fetch: all passed");
}

// http.fetch: what Go's http.Client.Do adds to a transport: redirects,
// cookies, authentication, the proxies of the environment, gzip, and the
// fields every request gets. Built on http.client's round_trip.
//
//   var c = http::Client { .. };
//   http::proxy_from_environment(c);             // HTTP_PROXY, HTTPS_PROXY, NO_PROXY
//   http::enable_cookies(c);                     // a jar, with the public suffix list
//   var r = http::get(c, "https://example.com/");
//   if r.err == 0 { print(r.status, " ", http::response_body(r).len); }
//
// fetch() gives the response with its body still to read (read_body, or
// read_all); get, head, post, post_form and request read it all.
//
// Redirects follow Go's rules (client.go): 301, 302 and 303 turn a method
// other than GET or HEAD into GET without a body, 307 and 308 keep the
// method and send the body again, at most max_redirects (10) are
// followed; Authorization, Cookie and the other sensitive fields set on
// the first request go only to its host and its subdomains; a Referer is
// sent, but not from https to http.
//
// Credentials: a URL's userinfo goes as Basic before any challenge, as Go
// sends it; set_credentials' go to the first URL's host and its
// subdomains as the client's auth option says (Basic at once, or in
// answer to a 401 with the scheme it asks for, Digest before Basic); a
// proxy URL's userinfo goes to the proxy as Basic, or answers its 407.

namespace http;

import std;
import os;
import http;
import h1;
import conn1;
import url;
import cookie;
import auth;
import flate;
import client;
import tls from "../tlsgoose.git";
import tls.handshake;

// --- Settings --------------------------------------------------------------

// Credentials for servers: sent as the client's opt.auth says.
fn set_credentials(c: Client&, user: const u8[:], password: const u8[:]) {
    c.user.clear();
    c.user.append(user);
    c.password.clear();
    c.password.append(password);
}

// A token sent as "Authorization: Bearer" to the first URL's host.
fn set_bearer(c: Client&, token: const u8[:]) {
    c.bearer.clear();
    c.bearer.append(token);
}

// One proxy for every URL, as Go's http.ProxyURL ("http://", "https://",
// "socks5://" or "socks5h://"; userinfo for its credentials), but the
// hosts of `no_proxy` (NO_PROXY's syntax; empty for none); an empty proxy
// for none. False if it is not such a URL.
fn set_proxy(c: Client&, proxy: const u8[:], no_proxy: const u8[:]) -> bool {
    c.proxy_http.clear();
    c.proxy_https.clear();
    c.no_proxy.clear();
    c.no_proxy.append(no_proxy);
    c.proxy_cgi = false;
    if proxy.len == 0 { c.proxy_mode = PROXY_NONE; return true; }
    let pu, e = url_parse(proxy);
    let sc = url_scheme(pu);
    if e != URL_OK || span_len(pu.host) == 0 || (sc != "http" && sc != "https" && sc != "socks5" && sc != "socks5h") {
        c.proxy_mode = PROXY_NONE;
        return false;
    }
    c.proxy_mode = PROXY_URL;
    c.proxy_http.append(proxy);
    c.proxy_https.append(proxy);
    return true;
}

fn env_any(a: const u8[:], b: const u8[:], out: u8[>..]&) {
    out.clear();
    if env(a, out) && out.len > 0 { return; }
    out.clear();
    if env(b, out) && out.len > 0 { return; }
    out.clear();
}

// Go's ProxyFromEnvironment: HTTP_PROXY (or http_proxy) for http URLs,
// HTTPS_PROXY (or https_proxy) for https ones, unless NO_PROXY (or
// no_proxy) names the host; never for localhost or a loopback address;
// HTTP_PROXY not at all when REQUEST_METHOD is set (a CGI program, whose
// HTTP_PROXY a request's Proxy field can set).
fn proxy_from_environment(c: Client&) {
    env_any("HTTP_PROXY", "http_proxy", c.proxy_http);
    env_any("HTTPS_PROXY", "https_proxy", c.proxy_https);
    env_any("NO_PROXY", "no_proxy", c.no_proxy);
    var rm: u8[>..] = [];
    c.proxy_cgi = env("REQUEST_METHOD", rm) && rm.len > 0;
    c.proxy_mode = PROXY_ENV;
}

// Keeps cookies in the client's jar, with publicsuffix.org's list built in
// so that no site sets cookies for a registry such as co.uk.
fn enable_cookies(c: Client&) {
    c.opt.cookies = true;
    if psl_empty(c.psl) { psl_builtin(c.psl); }
}

// Trusts the certificates of a PEM text (and not the system's roots). False
// if it has none.
fn set_roots_der(c: Client&, der_concat: const u8[:]) -> bool {
    if der_concat.len == 0 { return false; }
    c.tlscfg = tls::client_config("", der_concat);
    return true;
}

// --- Fetching --------------------------------------------------------------

fn wall_ms() -> i64 { time_ns() / 1000000 }

// Go's isDomainOrSubdomain on two URLs' host names (ASCII, lowered).
fn same_site_for_credentials(initial: const Url&, dest: const Url&) -> bool {
    let ih, ok1 = cookie_host(initial);
    let dh, ok2 = cookie_host(dest);
    if !ok1 || !ok2 { return false; }
    if ih[..] == dh[..] { return true; }
    if position(dh, ':') >= 0 || position(dh, '%') >= 0 { return false; }
    return has_dot_suffix(dh, ih);
}

fn is_sensitive(name: const u8[:]) -> bool {
    return eq_fold(name, "Authorization") || eq_fold(name, "Www-Authenticate") || eq_fold(name, "Cookie") ||
           eq_fold(name, "Cookie2") || eq_fold(name, "Proxy-Authorization") || eq_fold(name, "Proxy-Authenticate");
}

fn is_body_field(name: const u8[:]) -> bool {
    return eq_fold(name, "Content-Encoding") || eq_fold(name, "Content-Language") || eq_fold(name, "Content-Location") ||
           eq_fold(name, "Content-Type");
}

// The first request's fields as a redirect's request gets them (Go's
// makeHeadersCopier).
fn copy_fields(fields: const u8[:], strip_sensitive: bool, strip_body: bool) -> u8[>..] {
    var out: u8[>..] = [];
    var pos = 0;
    while pos < fields.len {
        var end = find(fields[pos..], "\r\n");
        end = if end < 0 { fields.len } else { pos + end };
        let line = fields[pos..end];
        let colon = position(line, ':');
        if colon > 0 {
            let name = line[..colon];
            if !(strip_sensitive && is_sensitive(name)) && !(strip_body && is_body_field(name)) {
                out.append(line);
                out.append("\r\n");
            }
        }
        pos = end + 2;
    }
    return out;
}

fn has_field(fields: const u8[:], name: const u8[:]) -> bool {
    let v, ok = field_value(fields, name);
    return ok;
}

// The Authorization value answering a challenge with the given credentials:
// Digest if offered and allowed, else Basic if allowed. Empty if none fits.
// The Digest challenge's params answered go to `chosen`.
fn answer_challenge(fields: const u8[:], field: const u8[:], user: const u8[:], password: const u8[:], mode: u8,
                    method: const u8[:], target: const u8[:], body: const u8[:], chosen: u8[>..]&) -> u8[>..] {
    chosen.clear();
    var digest: u8[>..] = [];
    var has_digest = false;
    var has_basic = false;
    each_field(fields, field) { v =>
        each_challenge(v) { scheme, params =>
            if eq_fold(scheme, "Digest") && !has_digest {
                var d: u8[>..] = [];
                if digest_credentials(d, params, user, password, method, target, body, 1, "") {
                    digest.append(d);
                    chosen.append(params);
                    has_digest = true;
                }
            } else if eq_fold(scheme, "Basic") {
                has_basic = true;
            }
        };
    };
    var out: u8[>..] = [];
    if has_digest && (mode == AUTH_ANY || mode == AUTH_DIGEST) { out.append(digest); }
    else if has_basic && (mode == AUTH_ANY || mode == AUTH_BASIC) { basic_credentials(out, user, password); chosen.clear(); }
    else { chosen.clear(); }
    return out;
}

// Whether a URL is in the protection space of the Digest challenge the
// client answered (RFC 7616 §3.3): the URIs its domain param lists (a
// prefix of the path, on the same origin), else the whole origin.
fn in_digest_space(c: const Client&, u: const Url&) -> bool {
    if c.digest_base.len == 0 { return false; }
    let base, be = url_parse(c.digest_base);
    if be != URL_OK { return false; }
    var here: u8[>..] = [];
    if !origin_key(u, here) { return false; }
    let dom, has_dom = auth_param(c.digest_params, "domain");
    if !has_dom || trim_ows(dom).len == 0 {
        var there: u8[>..] = [];
        return origin_key(base, there) && here[..] == there[..];
    }
    var hit = false;
    each_split(dom, ' ') {
        if it.len > 0 && !hit {
            let d, de = url_resolve(base, it);
            var there: u8[>..] = [];
            if de == URL_OK && origin_key(d, there) && here[..] == there[..] {
                let dp = url_path(d);
                let up = url_path(u);
                // "/a" covers "/a" and what is under it, "/a/" what is under it.
                if dp.len == 0 || (starts_with(up, dp) && (up.len == dp.len || dp[dp.len - 1] == '/' || up[dp.len] == '/')) {
                    hit = true;
                }
            }
        }
    };
    return hit;
}

fn forget_digest(c: Client&) {
    c.digest_base.clear();
    c.digest_params.clear();
    c.digest_user.clear();
    c.digest_password.clear();
    c.digest_nc = 0;
}

// The proxy's credentials (its URL's userinfo), for a URL.
fn proxy_userinfo(c: const Client&, u: const Url&) -> u8[>..], u8[>..], bool {
    let p = proxy_for(c, u);
    var user: u8[>..] = [];
    var pass: u8[>..] = [];
    if p.len == 0 { return user, pass, false; }
    let pu, e = url_parse(p);
    if e != URL_OK || !pu.has_user { return user, pass, false; }
    user.append(url_username(pu));
    pass.append(url_password(pu));
    let sc = url_scheme(pu);
    return user, pass, sc == "http" || sc == "https";
}

// A response with its fields changed: Content-Encoding and Content-Length
// dropped, as Go does when it decodes a gzip body.
fn drop_coding_fields(r: Response&) {
    let f = response_fields(r);
    var nf = fields_without(f, "Content-Encoding");
    let nf2 = fields_without(nf, "Content-Length");
    // Rebuild data: url, reason, fields; the body has not been read yet.
    var url_t: u8[>..] = [];
    url_t.append(response_url(r));
    var reason: u8[>..] = [];
    reason.append(response_reason(r));
    r.data.clear();
    r.data.append(url_t);
    r.url = span(0, r.data.len);
    let rp = r.data.len;
    r.data.append(reason);
    r.reason = span(rp, r.data.len);
    let fp = r.data.len;
    r.data.append(nf2);
    r.fields = span(fp, r.data.len);
    r.body = span(r.data.len, r.data.len);
    r.trailer = r.body;
}

// A request with the client's policy: the response with its head read and
// its body to read (read_body, read_all), or r.err set. A redirect that
// cannot be followed past max_redirects gives the last response with
// ERR_REDIRECTS (its body closed), as Go gives it with an error.
fn fetch(c: Client&, method0: const u8[:], url_text: const u8[:], fields: const u8[:], body: const u8[:]) -> Response {
    return fetch_core(c, method0, url_text, fields, body, false, 0, false) { out: u8[>..]&, start: bool => false };
}

// fetch, the body read as it is sent: F(out, start) appends the next of
// it to out and says whether more follows; `start` is true at the first
// call of each sending, when a `rewindable` body starts again from its
// beginning (Go's GetBody). F is a block `{ out: u8[>..]&, start: bool =>
// ... }`. `length` is the body's length (-1: unknown, sent in chunks). A
// hop that would send the body again (a 307 or 308, credentials
// answering a 401 or 407) after some of a body that is not rewindable has
// gone gives that response instead, as Go does without GetBody; with
// "Expect: 100-continue" in the fields such an answer may come before the
// body goes, and the hop goes ahead.
fn fetch_stream<F>(c: Client&, method0: const u8[:], url_text: const u8[:], fields: const u8[:], length: i64,
                   rewindable: bool) -> Response {
    return fetch_core(c, method0, url_text, fields, "", true, length, rewindable) { out: u8[>..]&, start: bool => F(out, start) };
}

fn fetch_core<F>(c: Client&, method0: const u8[:], url_text: const u8[:], fields: const u8[:], body: const u8[:],
                 stream: bool, length: i64, rewindable: bool) -> Response {
    c.deadline = if c.opt.timeout_ms > 0 { clock_ns() + c.opt.timeout_ms * 1000000 } else { 0 };
    let u0, ue = url_parse(url_text);
    if ue != URL_OK || url_check_http(u0) != URL_OK { return empty_response(ERR_URL); }
    var cur = copy(u0);
    var prev = copy(u0);
    var method: u8[>..] = [];
    method.append(method0);
    var include_body = true;
    var strip_sensitive = false;
    var redirects = 0;
    var host_override: u8[>..] = [];
    let given_host, has_host = field_value(fields, "Host");
    if has_host { host_override.append(given_host); }
    var authz: u8[>..] = [];        // an Authorization answering this hop's challenge
    var auth_tried = false;
    var proxy_tried = false;
    var consumed = false;           // some of a streamed body has been read
    while true {
        // This hop's fields.
        var f = copy_fields(fields, strip_sensitive, !include_body);
        remove_field(f, "Host");
        if host_override.len > 0 { add_field(f, "Host", host_override); }
        if redirects > 0 {
            let to_plain = url_https(prev) && !url_https(cur);
            if to_plain { remove_field(f, "Referer"); }
            else if !has_field(f, "Referer") { add_field(f, "Referer", url_referer(prev)); }
        }
        let creds_here = c.user.len > 0 && same_site_for_credentials(u0, cur);
        let bearer_here = c.bearer.len > 0 && same_site_for_credentials(u0, cur);
        // The credentials for this URL, if there are any.
        var user: u8[>..] = [];
        var pass: u8[>..] = [];
        var have = false;
        var mode = c.opt.auth;
        if cur.has_user { user.append(url_username(cur)); pass.append(url_password(cur)); have = true; mode = AUTH_ANY; }
        else if creds_here { user.append(c.user); pass.append(c.password); have = true; }
        var sent_digest = false;
        if authz.len > 0 {
            remove_field(f, "Authorization");
            add_field(f, "Authorization", authz);
        } else if !has_field(f, "Authorization") && have && mode != AUTH_BASIC && in_digest_space(c, cur)
                  && user[..] == c.digest_user[..] && pass[..] == c.digest_password[..] {
            // The challenge answered before, again with the next nc (RFC
            // 7616 §3.4), so no 401 comes first.
            var target: u8[>..] = [];
            request_target(cur, target);
            var d: u8[>..] = [];
            if digest_credentials(d, c.digest_params, user, pass, method, target, if include_body { body } else { "" },
                                  c.digest_nc + 1, "") {
                c.digest_nc++;
                add_field(f, "Authorization", d);
                sent_digest = true;
            }
        } else if !has_field(f, "Authorization") {
            if cur.has_user {
                var b: u8[>..] = [];
                basic_credentials(b, url_username(cur), url_password(cur));
                add_field(f, "Authorization", b);
            } else if creds_here && c.opt.auth == AUTH_BASIC {
                var b: u8[>..] = [];
                basic_credentials(b, c.user, c.password);
                add_field(f, "Authorization", b);
            } else if bearer_here {
                var b: u8[>..] = [];
                bearer_credentials(b, c.bearer);
                add_field(f, "Authorization", b);
            }
        }
        if c.opt.cookies {
            var jc: u8[>..] = [];
            if jar_cookie_header(c.jar, c.psl, cur, wall_ms(), jc) {
                let had, hok = field_value(f, "Cookie");
                var line: u8[>..] = [];
                if hok && had.len > 0 { line.append(had); line.append("; "); }
                line.append(jc);
                remove_field(f, "Cookie");
                add_field(f, "Cookie", line);
            }
        }
        if c.opt.user_agent.len > 0 && !has_field(f, "User-Agent") { add_field(f, "User-Agent", c.opt.user_agent[..]); }
        let want_gzip = c.opt.compression && !has_field(f, "Accept-Encoding") && !has_field(f, "Range") && method[..] != "HEAD";
        if want_gzip { add_field(f, "Accept-Encoding", "gzip"); }
        // The proxy's credentials, unless a 407 was answered already.
        if !proxy_tried {
            c.proxy_authz.clear();
            let pu_user, pu_pass, has_pcred = proxy_userinfo(c, cur);
            if has_pcred { basic_credentials(c.proxy_authz, pu_user, pu_pass); }
        }
        let streaming = stream && include_body;
        var r = if streaming { begin_request(c, method, cur, fields_without(f, "Transfer-Encoding"), length) }
                else { round_trip(c, method, cur, f, if include_body { body } else { "" }) };
        if streaming && r.err == ERR_NONE {
            var piece: u8[>..] = [];
            var more = true;
            var start = true;
            while more && !r.early && r.write_err == ERR_NONE {
                piece.clear();
                more = F(piece, start);
                start = false;
                consumed = true;
                if piece.len > 0 && write_body(c, r, piece) == ERR_REQUEST { break; }
            }
            end_request(c, r, "");
        }
        // A hop that sends the body again needs one that is still to read.
        let resend_ok = !streaming || !consumed || rewindable;
        // A proxy that wants other credentials for a tunnel (407 to CONNECT).
        if r.err == ERR_PROXY && c.proxy_status == 407 && !proxy_tried {
            let pu_user, pu_pass, has_pcred = proxy_userinfo(c, cur);
            if has_pcred {
                var at: u8[>..] = [];
                host_port_text(cur, at);
                var chosen: u8[>..] = [];
                let a = answer_challenge(c.proxy_fields, "Proxy-Authenticate", pu_user, pu_pass, AUTH_ANY, "CONNECT", at, "", chosen);
                if a.len > 0 && a[..] != c.proxy_authz[..] {
                    c.proxy_authz.clear();
                    c.proxy_authz.append(a);
                    proxy_tried = true;
                    continue;
                }
            }
        }
        if r.err != ERR_NONE {
            if r.err == ERR_PROXY && c.proxy_status != 0 { r.status = c.proxy_status; }
            r.redirects = redirects;
            return r;
        }
        if c.opt.cookies {
            let now = wall_ms();
            each_field(response_fields(r), "Set-Cookie") { v => jar_set_cookie(c.jar, c.psl, cur, v, now); };
        }
        // A Digest answer refused: the challenge is not answered again
        // unasked.
        if r.status == 401 && auth_tried && c.digest_params.len > 0 { forget_digest(c); }
        // 401 and 407 answered once a hop, with the credentials there are.
        if r.status == 401 && !auth_tried {
            if have {
                var target: u8[>..] = [];
                request_target(cur, target);
                var chosen: u8[>..] = [];
                let a = answer_challenge(response_fields(r), "WWW-Authenticate", user, pass, mode, method,
                                         target, if include_body { body } else { "" }, chosen);
                // An answer the same as what was sent (Basic at once, a server
                // that asks for Basic again) would get the same 401.
                let sent, had = field_value(f, "Authorization");
                if a.len > 0 && !(had && sent == a[..]) && resend_ok {
                    close_body(c, r);
                    authz.clear();
                    authz.append(a);
                    auth_tried = true;
                    forget_digest(c);
                    if chosen.len > 0 {
                        // Kept to answer this protection space's next
                        // requests at once.
                        c.digest_base.append(http::url_text(cur));
                        c.digest_params.append(chosen);
                        c.digest_user.append(user);
                        c.digest_password.append(pass);
                        c.digest_nc = 1;
                    }
                    continue;
                }
            }
            if sent_digest { forget_digest(c); }
        }
        if r.status == 407 && !proxy_tried {
            let pu_user, pu_pass, has_pcred = proxy_userinfo(c, cur);
            if has_pcred {
                var target: u8[>..] = [];
                absolute_target(cur, target);
                var chosen: u8[>..] = [];
                let a = answer_challenge(response_fields(r), "Proxy-Authenticate", pu_user, pu_pass, AUTH_ANY, method,
                                         target, if include_body { body } else { "" }, chosen);
                if a.len > 0 && a[..] != c.proxy_authz[..] && resend_ok {
                    close_body(c, r);
                    c.proxy_authz.clear();
                    c.proxy_authz.append(a);
                    proxy_tried = true;
                    continue;
                }
            }
        }
        // Redirects.
        let st = r.status;
        // 307 and 308 send the body again (Go: unless it cannot be had again).
        let redirect = st == 301 || st == 302 || st == 303 || ((st == 307 || st == 308) && (resend_ok || !include_body));
        if !redirect || !c.opt.follow_redirects {
            finish_response(c, r, want_gzip, redirects);
            return r;
        }
        let loc, has_loc = response_header(r, "Location");
        if !has_loc {
            finish_response(c, r, want_gzip, redirects);
            return r;
        }
        let next, le = url_resolve(cur, loc);
        if le != URL_OK {
            close_body(c, r);
            r.err = ERR_PROTOCOL;
            r.redirects = redirects;
            return r;
        }
        if redirects >= c.opt.max_redirects {
            close_body(c, r);
            r.err = ERR_REDIRECTS;
            r.redirects = redirects;
            return r;
        }
        // Go's redirectBehavior.
        if st == 301 || st == 302 || st == 303 {
            if method[..] != "GET" && method[..] != "HEAD" { method.clear(); method.append("GET"); }
            include_body = false;
        }
        // A relative Location keeps a Host given with the first request.
        let lr, lre = url_parse(loc);
        if lre != URL_OK || is_abs(lr) || lr.has_authority { host_override.clear(); }
        if !strip_sensitive && url_host(u0) != url_host(next) && !same_site_for_credentials(u0, next) {
            strip_sensitive = true;
        }
        close_body(c, r);
        prev = copy(cur);
        cur = copy(next);
        redirects++;
        authz.clear();
        auth_tried = false;
    }
    return empty_response(ERR_IO);
}

// The response handed back: its gzip body decoded as it is read.
fn finish_response(c: Client&, r: Response&, want_gzip: bool, redirects: i64) {
    r.redirects = redirects;
    let ce, has_ce = response_header(r, "Content-Encoding");
    if want_gzip && has_ce && eq_fold(ce, "gzip") && !r.body_done {
        drop_coding_fields(r);
        r.decode = true;
        r.inflate = inflate_slot(c);
    }
}

// fetch, and the body read whole into r.body.
fn request(c: Client&, method: const u8[:], url_text: const u8[:], fields: const u8[:], body: const u8[:]) -> Response {
    var r = fetch(c, method, url_text, fields, body);
    if r.err == ERR_NONE { read_all(c, r); }
    return r;
}

fn get(c: Client&, url_text: const u8[:]) -> Response { request(c, "GET", url_text, "", "") }
fn head(c: Client&, url_text: const u8[:]) -> Response { request(c, "HEAD", url_text, "", "") }

fn post(c: Client&, url_text: const u8[:], content_type: const u8[:], body: const u8[:]) -> Response {
    var f: u8[>..] = [];
    if content_type.len > 0 && !add_field(f, "Content-Type", content_type) { return empty_response(ERR_REQUEST); }
    return request(c, "POST", url_text, f, body);
}

// POST of a form built with form_add (Go's PostForm).
fn post_form(c: Client&, url_text: const u8[:], form: const u8[:]) -> Response {
    return post(c, url_text, "application/x-www-form-urlencoded", form);
}

// http.auth: HTTP authentication (RFC 9110 §11): the challenges of
// WWW-Authenticate and Proxy-Authenticate, and credentials for the Basic
// (RFC 7617), Bearer (RFC 6750) and Digest (RFC 7616) schemes.
//
//   each_challenge(value) { scheme, params => ... };     // params: "realm=\"x\", qop=auth" or a token68
//   var cred: u8[>..] = [];
//   http::basic_credentials(cred, "user", "pass");      // "Basic dXNlcjpwYXNz"
//
// Digest takes MD5, SHA-256 and SHA-512-256, each also as "-sess", qop
// "auth" and "auth-int" (the body hashed) or none (RFC 2069), userhash,
// and a user name outside ASCII as username* (RFC 8187).

namespace http;

import std;
import base64;
import http;
import url;
import bignum from "../bigmongoose.git";
import bignum.md5;
import bignum.sha256;
import bignum.sha512;
import bignum.entropy;

// --- Challenges (§11.2, §11.6.1) -------------------------------------------

fn skip_ows(s: const u8[:], i: i64) -> i64 {
    var k = i;
    while k < s.len && (s[k] == ' ' || s[k] == '\t') { k++; }
    return k;
}

fn token_end(s: const u8[:], i: i64) -> i64 {
    var k = i;
    while k < s.len && is_tchar(s[k]) { k++; }
    return k;
}

fn is_token68_char(c: u8) -> bool {
    return is_alnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/';
}

// Past a quoted-string starting at i (its opening quote), or -1 if it does
// not end.
fn quoted_end(s: const u8[:], i: i64) -> i64 {
    var k = i + 1;
    while k < s.len {
        if s[k] == '\\' { k += 2; continue; }
        if s[k] == '"' { return k + 1; }
        k++;
    }
    return -1;
}

// Whether at i an auth-param starts: token OWS "=".
fn param_starts(s: const u8[:], i: i64) -> bool {
    let e = token_end(s, i);
    if e == i { return false; }
    let k = skip_ows(s, e);
    // "token68" may end in "=" padding: a param has a value after its "=".
    if k >= s.len || s[k] != '=' { return false; }
    var v = skip_ows(s, k + 1);
    return v < s.len && s[v] != ',' && s[v] != '=';
}

// Each challenge of a WWW-Authenticate or Proxy-Authenticate value, as
// F(scheme, rest): rest is the challenge's token68 or its auth-params as
// written. Parsing stops at what is not a challenge.
fn each_challenge<F>(v: const u8[:]) {
    var i = 0;
    while true {
        // Empty list elements are skipped (§5.6.1).
        while i < v.len && (v[i] == ',' || v[i] == ' ' || v[i] == '\t') { i++; }
        if i >= v.len { return; }
        let se = token_end(v, i);
        if se == i { return; }
        let scheme = v[i..se];
        var k = se;
        var rest_start = skip_ows(v, k);
        var rest_end = rest_start;
        if k < v.len && (v[k] == ' ' || v[k] == '\t') {
            // token68: 1*( tchar68 ) *"=", alone up to a comma or the end.
            var t = rest_start;
            while t < v.len && is_token68_char(v[t]) { t++; }
            var u = t;
            while u < v.len && v[u] == '=' { u++; }
            let after = skip_ows(v, u);
            if t > rest_start && !param_starts(v, rest_start) && (after == v.len || v[after] == ',') {
                rest_end = u;
                k = after;
            } else {
                // auth-params: name=value pairs, until a token not followed by "=".
                var p = rest_start;
                var last = rest_start;
                while p < v.len {
                    p = skip_ows(v, p);
                    if !param_starts(v, p) { break; }
                    p = skip_ows(v, token_end(v, p));
                    p = skip_ows(v, p + 1);
                    if p < v.len && v[p] == '"' {
                        let q = quoted_end(v, p);
                        if q < 0 { return; }
                        p = q;
                    } else {
                        let te = token_end(v, p);
                        if te == p { return; }
                        p = te;
                    }
                    last = p;
                    p = skip_ows(v, p);
                    if p >= v.len { break; }
                    if v[p] != ',' { return; }
                    // Past commas; stop before the next challenge's scheme.
                    var q = p;
                    while q < v.len && (v[q] == ',' || v[q] == ' ' || v[q] == '\t') { q++; }
                    if q >= v.len || !param_starts(v, q) { p = q; break; }
                    p = q;
                }
                rest_end = last;
                k = p;
            }
        }
        F(scheme, v[rest_start..rest_end]);
        i = k;
    }
}

// The value of the auth-param `name` (any case) in a challenge's params,
// a quoted-string's escapes undone; false if absent.
fn auth_param(params: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var p = 0;
    while p < params.len {
        p = skip_ows(params, p);
        while p < params.len && (params[p] == ',' || params[p] == ' ' || params[p] == '\t') { p++; }
        let ne = token_end(params, p);
        if ne == p { break; }
        let pname = params[p..ne];
        p = skip_ows(params, ne);
        if p >= params.len || params[p] != '=' { break; }
        p = skip_ows(params, p + 1);
        var val: u8[>..] = [];
        if p < params.len && params[p] == '"' {
            let q = quoted_end(params, p);
            if q < 0 { break; }
            var k = p + 1;
            while k < q - 1 {
                if params[k] == '\\' && k + 1 < q - 1 { k++; }
                val.push(params[k]);
                k++;
            }
            p = q;
        } else {
            let te = token_end(params, p);
            val.append(params[p..te]);
            p = te;
        }
        if eq_fold(pname, name) { out.append(val); return out, true; }
    }
    return out, false;
}

// --- Basic and Bearer ------------------------------------------------------

// "Basic " and base64(user ":" password) (RFC 7617 §2), the bytes as given
// (UTF-8 is what charset="UTF-8" asks for).
fn basic_credentials(out: u8[>..]&, user: const u8[:], password: const u8[:]) {
    var up: u8[>..] = [];
    up.append(user);
    up.push(':');
    up.append(password);
    out.append("Basic ");
    base64::encode(out, up);
}

// "Bearer " and the token (RFC 6750 §2.1).
fn bearer_credentials(out: u8[>..]&, token: const u8[:]) {
    out.append("Bearer ");
    out.append(token);
}

// --- Digest (RFC 7616) -----------------------------------------------------

let DIGEST_MD5: u8 = 1;
let DIGEST_SHA256: u8 = 2;
let DIGEST_SHA512_256: u8 = 3;

fn put_hex_lower(out: u8[>..]&, b: const u8[:]) {
    let hx = "0123456789abcdef";
    for c in b { out.push(hx[c >> 4]); out.push(hx[c & 15]); }
}

// The hash, in lowercase hex, of `data` (§3.4.1's H).
fn digest_h(out: u8[>..]&, alg: u8, data: const u8[:]) {
    if alg == DIGEST_MD5 {
        let d = bignum::md5(data);
        put_hex_lower(out, d);
    } else if alg == DIGEST_SHA256 {
        let d = bignum::sha256(data);
        put_hex_lower(out, d);
    } else {
        var s = bignum::sha512_256_init();
        bignum::sha512_update(s, data);
        let d = bignum::sha512_final(s);
        put_hex_lower(out, d);
    }
}

fn digest_alg(name: const u8[:]) -> u8, bool, bool {
    var base = name;
    var sess = false;
    if name.len > 5 && eq_fold(name[name.len - 5..], "-sess") { sess = true; base = name[..name.len - 5]; }
    if base.len == 0 || eq_fold(base, "MD5") { return DIGEST_MD5, sess, true; }
    if eq_fold(base, "SHA-256") { return DIGEST_SHA256, sess, true; }
    if eq_fold(base, "SHA-512-256") { return DIGEST_SHA512_256, sess, true; }
    return 0, false, false;
}

// Whether s can go in a quoted-string as it is (no DQUOTE, backslash or
// control, and ASCII, so username= rather than username*=).
fn quotable_ascii(s: const u8[:]) -> bool {
    for c in s { if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' { return false; } }
    return true;
}

fn put_quoted(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c == '"' || c == '\\' { out.push('\\'); }
        out.push(c);
    }
    out.push('"');
}

// RFC 8187's ext-value: UTF-8''percent-encoded.
fn put_ext_value(out: u8[>..]&, s: const u8[:]) {
    out.append("UTF-8''");
    for c in s {
        if is_alnum(c) || c == '!' || c == '#' || c == '$' || c == '&' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~' {
            out.push(c);
        } else {
            put_escaped(out, c);
        }
    }
}

// A Digest response to a challenge's params (RFC 7616 §3.4): the
// Authorization (or Proxy-Authorization) value, appended to out. `uri` is
// the request target, `body` the request's body (for qop=auth-int), `nc`
// the count of requests this nonce has served (1 for the first), and
// `cnonce` the client nonce (random hex when empty). False if the
// challenge cannot be answered (no nonce or realm, an algorithm not
// known, a qop of neither auth nor auth-int).
fn digest_credentials(out: u8[>..]&, params: const u8[:], user: const u8[:], password: const u8[:],
                      method: const u8[:], uri: const u8[:], body: const u8[:], nc: i64, cnonce0: const u8[:]) -> bool {
    let realm, has_realm = auth_param(params, "realm");
    let nonce, has_nonce = auth_param(params, "nonce");
    let opaque, has_opaque = auth_param(params, "opaque");
    let algname, has_alg = auth_param(params, "algorithm");
    let qops, has_qop = auth_param(params, "qop");
    let uh, has_userhash = auth_param(params, "userhash");
    if !has_realm || !has_nonce { return false; }
    let alg, sess, aok = digest_alg(algname);
    if !aok { return false; }
    // qop: "auth" if offered, else "auth-int"; none when there is no qop.
    var qop: u8[>..] = [];
    if has_qop {
        var auth = false;
        var auth_int = false;
        each_split(qops, ',') {
            let q = trim_ows(it);
            if eq_fold(q, "auth") { auth = true; }
            if eq_fold(q, "auth-int") { auth_int = true; }
        };
        if auth { qop.append("auth"); } else if auth_int { qop.append("auth-int"); } else { return false; }
    }
    var cnonce: u8[>..] = [];
    if cnonce0.len > 0 { cnonce.append(cnonce0); } else {
        var r: u8[16] = [0; 16];
        bignum::random_bytes(r);
        put_hex_lower(cnonce, r);
    }
    var ncs: u8[>..] = [];
    format_uint(ncs, nc as! u64, 16, 8, '0');
    // A1, and HA1 (§3.4.2).
    var a1: u8[>..] = [];
    a1.append(user); a1.push(':'); a1.append(realm); a1.push(':'); a1.append(password);
    var ha1: u8[>..] = [];
    digest_h(ha1, alg, a1);
    if sess {
        var s1: u8[>..] = [];
        s1.append(ha1); s1.push(':'); s1.append(nonce); s1.push(':'); s1.append(cnonce);
        ha1.clear();
        digest_h(ha1, alg, s1);
    }
    // A2 (§3.4.3).
    var a2: u8[>..] = [];
    a2.append(method); a2.push(':'); a2.append(uri);
    if qop[..] == "auth-int" {
        a2.push(':');
        digest_h(a2, alg, body);
    }
    var ha2: u8[>..] = [];
    digest_h(ha2, alg, a2);
    // response = KD(HA1, nonce:nc:cnonce:qop:HA2), or KD(HA1, nonce:HA2) without qop.
    var kd: u8[>..] = [];
    kd.append(ha1); kd.push(':'); kd.append(nonce); kd.push(':');
    if qop.len > 0 { kd.append(ncs); kd.push(':'); kd.append(cnonce); kd.push(':'); kd.append(qop); kd.push(':'); }
    kd.append(ha2);
    var response: u8[>..] = [];
    digest_h(response, alg, kd);
    // The user name: hashed with userhash=true (§3.4.4), else as
    // username= or, outside ASCII, username* (§3.4.4, RFC 8187).
    out.append("Digest ");
    let hashed = has_userhash && eq_fold(uh, "true");
    if hashed {
        var u: u8[>..] = [];
        u.append(user); u.push(':'); u.append(realm);
        var hu: u8[>..] = [];
        digest_h(hu, alg, u);
        out.append("username=");
        put_quoted(out, hu);
    } else if quotable_ascii(user) {
        out.append("username=");
        put_quoted(out, user);
    } else {
        out.append("username*=");
        put_ext_value(out, user);
    }
    out.append(", realm=");
    put_quoted(out, realm);
    out.append(", uri=");
    put_quoted(out, uri);
    if has_alg { out.append(", algorithm="); out.append(algname); }
    out.append(", nonce=");
    put_quoted(out, nonce);
    if qop.len > 0 {
        out.append(", nc="); out.append(ncs);
        out.append(", cnonce="); put_quoted(out, cnonce);
        out.append(", qop="); out.append(qop);
    }
    out.append(", response=");
    put_quoted(out, response);
    if has_opaque { out.append(", opaque="); put_quoted(out, opaque); }
    if hashed { out.append(", userhash=true"); }
    return true;
}

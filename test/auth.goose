// http.auth: challenge parsing (RFC 9110 §11.6.1's example and edge
// cases), Basic (RFC 7617 §2's example), and Digest against RFC 7616
// §3.9's examples (SHA-256, MD5, and SHA-512-256 with userhash, as errata
// 4897 corrects it).

import std;
import bignum from "../../bigmongoose.git";
import http from "..";
import http.auth;

var failures = 0;

fn check(what: const u8[:], got: const u8[:], want: const u8[:]) {
    if got != want {
        print("FAIL ", what, ":\n  got  '", got, "'\n  want '", want, "'");
        failures++;
    }
}

fn challenges(v: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    http::each_challenge(v) { scheme, rest =>
        out.push('[');
        out.append(scheme);
        out.push('|');
        out.append(rest);
        out.push(']');
    };
    return out;
}

fn param(params: const u8[:], name: const u8[:]) -> u8[>..] {
    let v, ok = http::auth_param(params, name);
    var out: u8[>..] = [];
    if !ok { out.append("<none>"); } else { out.append(v); }
    return out;
}

fn parsing() {
    check("rfc 9110 example", challenges("Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\""),
          "[Newauth|realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"][Basic|realm=\"simple\"]");
    check("token68", challenges("Negotiate YIIB==, Basic realm=\"x\""), "[Negotiate|YIIB==][Basic|realm=\"x\"]");
    check("bare schemes", challenges("Negotiate, NTLM"), "[Negotiate|][NTLM|]");
    check("empty elements", challenges(", ,Basic realm=x,, Bearer"), "[Basic|realm=x][Bearer|]");
    check("bws around =", challenges("Basic realm = \"x\" , charset=\"UTF-8\""), "[Basic|realm = \"x\" , charset=\"UTF-8\"]");
    check("token68 with equals and param", challenges("A b=, B c=d"), "[A|b=][B|c=d]");
    check("unterminated quote", challenges("Basic realm=\"x"), "");
    check("param", param("realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"", "title"), "Login to \"apps\"");
    check("param case", param("Realm=\"r\"", "realm"), "r");
    check("param token", param("realm=\"r\", type=1", "type"), "1");
    check("param missing", param("realm=\"r\"", "nonce"), "<none>");
    check("param spaces", param("realm = \"x\" , charset = UTF-8", "charset"), "UTF-8");
    var b: u8[>..] = [];
    http::basic_credentials(b, "Aladdin", "open sesame");
    check("basic", b, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    var bt: u8[>..] = [];
    http::bearer_credentials(bt, "mF_9.B5f-4.1JqM");
    check("bearer", bt, "Bearer mF_9.B5f-4.1JqM");
}

fn digest() {
    // RFC 7616 §3.9.1.
    let ch = "realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    var a: u8[>..] = [];
    let ok = http::digest_credentials(a, ch, "Mufasa", "Circle of Life", "GET", "/dir/index.html", "", 1,
                                      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
    if !ok { print("FAIL digest sha-256: refused"); failures++; }
    check("digest sha-256", a, "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", uri=\"/dir/index.html\", algorithm=SHA-256, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc=00000001, cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop=auth, response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"");
    let ch5 = "realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=MD5, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    var m: u8[>..] = [];
    http::digest_credentials(m, ch5, "Mufasa", "Circle of Life", "GET", "/dir/index.html", "", 1,
                             "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
    let at = find(m, "response=\"");
    check("digest md5", m[at..at + 43], "response=\"8ca523f5e9506fed4657c9700eebdbec\"");
    // RFC 7616 §3.9.2: SHA-512-256, userhash, a user name outside ASCII. The
    // values printed there are not SHA-512/256 of FIPS 180-4; these are
    // errata 4897's corrected ones (Python's hashlib agrees).
    let chu = "realm=\"api@example.org\", qop=\"auth\", algorithm=SHA-512-256, nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", charset=UTF-8, userhash=true";
    var u: u8[>..] = [];
    http::digest_credentials(u, chu, "J\xc3\xa4s\xc3\xb8n Doe", "Secret, or not?", "GET", "/doe.json", "", 1,
                             "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v");
    let uat = find(u, "username=\"");
    check("userhash", u[uat..uat + 75], "username=\"793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b\"");
    let rat = find(u, "response=\"");
    check("digest sha-512-256", u[rat..rat + 75], "response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\"");
    // §3.4.4 without userhash: the name outside ASCII as username*.
    let chn = "realm=\"api@example.org\", qop=\"auth\", algorithm=SHA-512-256, nonce=\"n\"";
    var n: u8[>..] = [];
    http::digest_credentials(n, chn, "J\xc3\xa4s\xc3\xb8n Doe", "x", "GET", "/", "", 1, "c");
    check("username*", n[..find(n, ", realm")], "Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe");
    var bad: u8[>..] = [];
    if http::digest_credentials(bad, "realm=\"r\", nonce=\"n\", algorithm=SHA-1", "u", "p", "GET", "/", "", 1, "c") {
        print("FAIL unknown algorithm taken"); failures++;
    }
    if http::digest_credentials(bad, "realm=\"r\", nonce=\"n\", qop=\"other\"", "u", "p", "GET", "/", "", 1, "c") {
        print("FAIL unknown qop taken"); failures++;
    }
    if http::digest_credentials(bad, "realm=\"r\"", "u", "p", "GET", "/", "", 1, "c") {
        print("FAIL no nonce taken"); failures++;
    }
}

fn main() {
    parsing();
    digest();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("auth: all passed");
}

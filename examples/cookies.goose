// cookies: a browser's cookie handling, without a browser. Set-Cookie
// fields are read, a jar keeps the cookies by RFC 6265's rules (Go's
// cookiejar), the public suffix list stops a site setting a cookie for a
// whole registry, the Cookie field is made for each request, and the jar
// is saved as curl's cookies.txt and loaded again.
//
//   goose examples/cookies.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.url;
import http.cookie;

fn parsed(s: const u8[:]) -> http::Url {
    let u, e = http::url_parse(s);
    guard e == 0 else { print("cookies: ", s, ": ", http::url_error_text(e)); exit(1); }
    return u;
}

// The Cookie field a request to `url` carries, "" for none.
fn cookie_for(jar: http::Jar&, psl: const http::Psl&, url: const u8[:], now: i64) -> u8[>..] {
    let u = parsed(url);
    var line: u8[>..] = [];
    http::jar_cookie_header(jar, psl, u, now, line);
    return line;
}

fn expect(what: const u8[:], got: const u8[:], want: const u8[:]) {
    guard got == want else { print("cookies: ", what, ": got '", got, "', want '", want, "'"); exit(1); }
    print(what, ": ", if got.len > 0 { got } else { "(none)" });
}

fn main() {
    // One Set-Cookie field, read as a user agent reads it.
    let field = "session=abc123; Domain=shop.example.co.uk; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax";
    let sc, ok = http::parse_set_cookie(field);
    guard ok && sc.secure && sc.http_only && sc.max_age == 3600 && sc.same_site == http::SAMESITE_LAX else {
        print("cookies: Set-Cookie misread"); exit(1);
    }
    print("Set-Cookie: ", field[sc.name.pos..sc.name.end], " = ", field[sc.value.pos..sc.value.end], " for ",
          field[sc.domain.pos..sc.domain.end]);

    // The public suffix list, built into the program.
    var psl = http::empty_psl();
    guard http::psl_builtin(psl) > 0 else { print("cookies: no public suffix list"); exit(1); }
    let site, sok = http::registrable_domain(psl, "www.shop.example.co.uk");
    guard sok else { print("cookies: no registrable domain"); exit(1); }
    expect("registrable domain", site, "example.co.uk");

    // The jar, with responses from one site at time `now` (ms).
    var jar = http::new_jar();
    let now: i64 = 1790000000000;
    let from = parsed("https://www.shop.example.co.uk/login");
    guard http::jar_set_cookie(jar, psl, from, "lang=en; Domain=example.co.uk; Path=/", now) &&
          http::jar_set_cookie(jar, psl, from, "cart=3; Path=/cart; Max-Age=600", now) &&
          http::jar_set_cookie(jar, psl, from, "token=xyz; Secure", now) else {
        print("cookies: a cookie was refused"); exit(1);
    }
    // A Domain of co.uk is a public suffix: it would reach every UK site.
    guard !http::jar_set_cookie(jar, psl, from, "evil=1; Domain=co.uk", now) else {
        print("cookies: a cookie for co.uk was taken"); exit(1);
    }
    print("refused: a cookie for all of co.uk");

    // What each request sends.
    expect("Cookie to /cart", cookie_for(jar, psl, "https://www.shop.example.co.uk/cart/view", now), "cart=3; lang=en; token=xyz");
    expect("Cookie over http", cookie_for(jar, psl, "http://www.shop.example.co.uk/", now), "lang=en");
    expect("Cookie to a sister site", cookie_for(jar, psl, "https://blog.example.co.uk/", now), "lang=en");
    expect("Cookie to another site", cookie_for(jar, psl, "https://example.com/", now), "");
    // Eleven minutes on, the cart has expired.
    expect("Cookie later", cookie_for(jar, psl, "https://www.shop.example.co.uk/cart/", now + 660000), "lang=en; token=xyz");
    // Max-Age=0 removes one.
    http::jar_set_cookie(jar, psl, from, "lang=; Domain=example.co.uk; Path=/; Max-Age=0", now);
    expect("Cookie after logout", cookie_for(jar, psl, "https://www.shop.example.co.uk/", now), "token=xyz");

    // Saved as curl's cookies.txt (session cookies too), and loaded again.
    var text: u8[>..] = [];
    http::jar_save_netscape(jar, text, now, true);
    var again = http::new_jar();
    guard http::jar_load_netscape(again, psl, text, now) == http::jar_count(jar) else {
        print("cookies: the file did not load"); exit(1);
    }
    expect("Cookie from the file", cookie_for(again, psl, "https://www.shop.example.co.uk/", now), "token=xyz");
    print("jar: ", http::jar_count(jar), " cookie kept; now as an HTTP date: ", http_date(now));
}

fn http_date(ms: i64) -> u8[>..] {
    var d: u8[>..] = [];
    http::format_http_date(d, ms);
    let back, ok = http::parse_cookie_date(d);
    guard ok && back == ms / 1000 * 1000 else { print("cookies: the date did not read back"); exit(1); }
    return d;
}

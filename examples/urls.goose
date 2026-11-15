// urls: what a client does with URLs before it sends anything: parse one
// and read its parts, resolve a link found on a page against it, build a
// query string and read values back out of one, and write the request
// target and Host field that go on the wire (a host outside ASCII in
// its Punycode form).
//
//   goose examples/urls.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.url;

fn parsed(s: const u8[:]) -> http::Url {
    let u, e = http::url_parse(s);
    guard e == 0 else { print("urls: ", s, ": ", http::url_error_text(e)); exit(1); }
    return u;
}

fn expect(what: const u8[:], got: const u8[:], want: const u8[:]) {
    guard got == want else { print("urls: ", what, ": got '", got, "', want '", want, "'"); exit(1); }
    print(what, ": ", got);
}

fn main() {
    // The parts of a URL, the userinfo decoded.
    let u = parsed("https://al%40ice:s3cret@Example.COM:8443/docs/guide/intro.html?lang=en#install");
    expect("scheme", http::url_scheme(u), "https");
    expect("host", http::url_host(u), "Example.COM");
    expect("user", http::url_username(u), "al@ice");
    guard http::url_port(u) == 8443 else { print("urls: port"); exit(1); }
    expect("path", http::url_path(u), "/docs/guide/intro.html");
    expect("query", http::url_query(u), "lang=en");
    expect("fragment", http::url_fragment(u), "install");
    // What may be logged or sent as a Referer: no password, no fragment.
    expect("redacted", http::url_redacted(u), "https://al%40ice:xxxxx@Example.COM:8443/docs/guide/intro.html?lang=en#install");
    expect("referer", http::url_referer(u), "https://Example.COM:8443/docs/guide/intro.html?lang=en");

    // Links on that page, resolved against it (RFC 3986 §5.2).
    let links = ["../api/", "setup.html#top", "/index.html", "?lang=fr", "//cdn.example.com/x.js", "mailto:a@example.com"];
    let want = ["https://al%40ice:s3cret@Example.COM:8443/docs/api/",
                "https://al%40ice:s3cret@Example.COM:8443/docs/guide/setup.html#top",
                "https://al%40ice:s3cret@Example.COM:8443/index.html",
                "https://al%40ice:s3cret@Example.COM:8443/docs/guide/intro.html?lang=fr",
                "https://cdn.example.com/x.js", "mailto:a@example.com"];
    for i in links.len {
        let r, e = http::url_resolve(u, links[i]);
        guard e == 0 else { print("urls: cannot resolve ", links[i]); exit(1); }
        expect(links[i], http::url_text(r), want[i]);
    }

    // A query built as a form is (Go's Values.Encode), and read back.
    var q: u8[>..] = [];
    http::form_add(q, "q", "fish & chips");
    http::form_add(q, "city", "Zürich");
    expect("query built", q, "q=fish+%26+chips&city=Z%C3%BCrich");
    let city, found = http::query_value(q, "city");
    guard found else { print("urls: no city"); exit(1); }
    expect("city", city, "Zürich");
    var seg: u8[>..] = [];
    http::path_escape(seg, "annual report 2026/Q1.pdf");
    expect("path segment", seg, "annual%20report%202026%2FQ1.pdf");

    // What a request to a URL puts on the wire: the target and Host.
    let w = parsed("http://bücher.example/search?q=a b#results");
    var target: u8[>..] = [];
    http::request_target(w, target);
    expect("request target", target, "/search?q=a%20b");
    var host: u8[>..] = [];
    guard http::host_port_field(w, host) else { print("urls: no Host field"); exit(1); }
    expect("Host", host, "xn--bcher-kva.example");

    // URLs a client refuses.
    let bad, e1 = http::url_parse("http://example.com:80x/");
    guard e1 == http::URL_ERR_PORT else { print("urls: a bad port was taken"); exit(1); }
    print("refused: ", http::url_error_text(e1));
    let ftp = parsed("ftp://example.com/file");
    guard http::url_check_http(ftp) != 0 else { print("urls: ftp taken as http"); exit(1); }
    print("refused: ", http::url_error_text(http::url_check_http(ftp)));
}

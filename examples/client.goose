// client: the everyday HTTP client calls against a live server: GET with
// the response's status, fields and body; a request with fields of our
// own; a POST of JSON and of a form; HEAD; and the client's policy, set
// once on the Client: redirects (followed, or handed back), cookies kept
// in its jar between requests, gzip asked for and decoded, timeouts.
// HTTP/2 is used over TLS when the server offers it, else HTTP/1.1; the
// connections to one origin are kept and used again.
//
//   goose examples/client.goose -- URL
//   goose examples/client.goose -- http://127.0.0.1:8080/

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.url;
import http.client;
import http.fetch;

// One line about a response; false if the request failed.
fn show(what: const u8[:], r: const http::Response&) -> bool {
    if r.err != http::ERR_NONE {
        print(what, ": failed: ", http::client_error_text(r.err));
        return false;
    }
    var line: u8[>..] = [];
    format(line, what, ": ", r.status, " ", http::response_reason(r), if r.h2 { " (HTTP/2)" } else { "" }, ", ",
           http::response_body(r).len, " bytes");
    let ctype, has_ctype = http::response_header(r, "Content-Type");
    if has_ctype { format(line, " of ", ctype); }
    if r.redirects > 0 { format(line, ", after ", r.redirects, " redirect(s), at ", http::response_url(r)); }
    print(line);
    return true;
}

fn main() {
    let a = args();
    guard a.len == 2 else { print("usage: client URL"); exit(2); }
    let url = a[1];
    let u, ue = http::url_parse(url);
    guard ue == 0 && http::url_check_http(u) == 0 else { print("client: not an http or https URL: ", url); exit(2); }

    // The client and its policy. A Client is a root struct: it lives in
    // main and is passed by reference.
    var c = http::Client { .. };
    c.opt.timeout_ms = 15000;               // each request, redirects and body included
    c.opt.max_redirects = 5;
    http::enable_cookies(c);                // a jar, with the public suffix list
    http::proxy_from_environment(c);        // HTTP_PROXY, HTTPS_PROXY, NO_PROXY

    // GET, the body read whole into the response.
    var r = http::get(c, url);
    guard show("GET", r) else { exit(1); }
    http::each_field(http::response_fields(r), "Set-Cookie") { v => print("  Set-Cookie: ", v); };
    // The cookies it set go back with the next request to this site.
    var cookie: u8[>..] = [];
    if http::jar_cookie_header(c.jar, c.psl, u, http::wall_ms(), cookie) { print("  the jar now sends: Cookie: ", cookie); }

    // A request with fields of our own (checked as they are added).
    var f: u8[>..] = [];
    http::add_field(f, "Accept", "application/json");
    http::add_field(f, "X-Request-Id", "example-0001");
    r = http::request(c, "GET", url, f, "");
    show("GET with fields", r);
    print("  on a connection used before: ", r.reused);

    // HEAD: the head alone.
    r = http::head(c, url);
    show("HEAD", r);

    // POST: a JSON body, then a form (application/x-www-form-urlencoded).
    r = http::post(c, url, "application/json", "{\"name\":\"widget\",\"count\":3}");
    show("POST JSON", r);
    var form: u8[>..] = [];
    http::form_add(form, "q", "fish & chips");
    http::form_add(form, "page", "2");
    r = http::post_form(c, url, form);
    show("POST form", r);

    // Redirects handed back instead of followed: a 3xx and its Location.
    c.opt.follow_redirects = false;
    r = http::get(c, url);
    if show("GET, redirects not followed", r) && r.status >= 300 && r.status < 400 {
        let loc, has_loc = http::response_header(r, "Location");
        print("  Location: ", if has_loc { loc } else { "(none)" });
    }
    http::close_idle(c);
}

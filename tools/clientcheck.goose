// clientcheck: http.client and http.fetch driven directly, with several
// responses open at once, against gointerop's server; for interop.py.
//
//	goose tools/clientcheck.goose -- BASE [--cacert c.pem]
//
// One line a check, "ok NAME" or "FAIL NAME: why"; exit status 1 if any
// failed.

import std;
import os;
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls from "../../tlsgoose.git";
import tls.handshake;
import http from "..";
import http.url;
import http.cookie;
import http.client;
import http.fetch;

var failed = false;

fn report(name: const u8[:], why: const u8[:]) {
    var l: u8[>..] = [];
    if why.len == 0 { l.append("ok "); l.append(name); }
    else { l.append("FAIL "); l.append(name); l.append(": "); l.append(why); failed = true; }
    l.push('\n');
    write_stdout(l);
    flush_stdout();
}

// gointerop's big(): 1 MiB.
fn big() -> u8[>..] {
    var b: u8[>..] = [];
    for i in 1 << 20 { b.push(((i * 7 + (i >> 8)) & 0xff) as! u8); }
    return b;
}

fn url(base: const u8[:], path: const u8[:]) -> u8[>..] {
    var u: u8[>..] = [];
    u.append(base);
    u.append(path);
    return u;
}

// Reads the bodies of the responses in turns, `step` bytes or so at a
// time each; "" if each is `want`.
fn read_in_turns(c: http::Client&, a: http::Response&, b: http::Response&, want_a: const u8[:], want_b: const u8[:]) -> u8[>..] {
    var why: u8[>..] = [];
    if a.err != 0 || b.err != 0 {
        why.append(str("err ", a.err, " and ", b.err));
        return why;
    }
    var ba: u8[>..] = [];
    var bb: u8[>..] = [];
    var rounds = 0;
    while (!a.body_done || !b.body_done) && rounds < 100000 {
        rounds++;
        if !a.body_done {
            let n = http::read_body(c, a, ba);
            if n < 0 { why.append(str("the first failed: ", http::client_error_text(-n))); return why; }
        }
        if !b.body_done {
            let n = http::read_body(c, b, bb);
            if n < 0 { why.append(str("the second failed: ", http::client_error_text(-n))); return why; }
        }
    }
    if ba[..] != want_a { why.append(str("the first body has ", ba.len, " bytes, not the ones sent")); }
    else if bb[..] != want_b { why.append(str("the second body has ", bb.len, " bytes, not the ones sent")); }
    return why;
}

fn main() {
    let a = args();
    if a.len < 2 { write_stderr("usage: clientcheck BASE [--cacert c.pem]\n"); exit(2); }
    let base = a[1];
    var c = http::Client { .. };
    if a.len >= 4 && a[2] == "--cacert" {
        var text: u8[>..] = [];
        if !read_file(a[3], text) { write_stderr("clientcheck: cannot read the roots\n"); exit(2); }
        let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
        var der: u8[>..] = [];
        for d in ders { der.append(d); }
        http::set_roots_der(c, der);
    }
    let want = big();
    // Two at once, each on its connection, read in turns.
    var r1 = http::fetch(c, "GET", url(base, "/big"), "", "");
    var r2 = http::fetch(c, "GET", url(base, "/big"), "", "");
    report("two responses open at once, read in turns", read_in_turns(c, r1, r2, want, want));
    var g1 = http::fetch(c, "GET", url(base, "/gzip"), "", "");
    var p1 = http::fetch(c, "GET", url(base, "/big"), "", "");
    var why: u8[>..] = [];
    if !g1.decode { why.append("the gzip one is not decoded"); } else { why.append(read_in_turns(c, g1, p1, want, want)); }
    report("gzip and not, read in turns", why);
    var g2 = http::fetch(c, "GET", url(base, "/gzip"), "", "");
    var g3 = http::fetch(c, "GET", url(base, "/gzip"), "", "");
    report("two gzip bodies decoded in turns", read_in_turns(c, g2, g3, want, want));
    // One left open while another is fetched whole, then read.
    var l1 = http::fetch(c, "GET", url(base, "/big"), "", "");
    var h = http::request(c, "GET", url(base, "/hello"), "", "");
    var why2: u8[>..] = [];
    if h.err != 0 || http::response_body(h) != "hello" { why2.append(str("the second: err ", h.err)); }
    else {
        var rest: u8[>..] = [];
        while !l1.body_done { if http::read_body(c, l1, rest) < 0 { why2.append("the first failed"); break; } }
        if why2.len == 0 && rest[..] != want { why2.append(str("the first has ", rest.len, " bytes")); }
    }
    report("one left open while another comes whole", why2);
    // Two uploads begun, their bodies sent in turns, then both read.
    let ua, ue = http::url_parse(url(base, "/echo"));
    var u1 = http::begin_request(c, "POST", ua, "", want.len);
    var u2 = http::begin_request(c, "POST", ua, "", -1);
    var why3: u8[>..] = [];
    if u1.err != 0 || u2.err != 0 { why3.append(str("begin: ", u1.err, " ", u2.err)); }
    else {
        var at = 0;
        while at < want.len {
            let n = if want.len - at < 50000 { want.len - at } else { 50000 };
            http::write_body(c, u1, want[at..at + n]);
            http::write_body(c, u2, want[want.len - at - n..want.len - at]);
            at += n;
        }
        http::end_request(c, u1, "");
        http::end_request(c, u2, "X-Done: yes\r\n");
        var back: u8[>..] = [];
        var back2: u8[>..] = [];
        // The second's body went last piece first.
        var rev: u8[>..] = [];
        var k = want.len;
        while k > 0 {
            let n = if k < 50000 { k } else { 50000 };
            rev.append(want[k - n..k]);
            k -= n;
        }
        why3.append(read_in_turns(c, u1, u2, want, rev));
    }
    report("two uploads sent in turns, then read in turns", why3);
    http::close_idle(c);
    exit(if failed { 1 } else { 0 });
}

// client_streams: the client's streaming calls against a live server. An
// upload whose body is made as it is sent (never whole in memory), in
// chunks; a download read a piece at a time; and three requests open at
// once, their bodies read in turns: on HTTP/2 they share one connection
// as streams, on HTTP/1.1 each has its own.
//
//   goose examples/client_streams.goose -- URL [UPLOAD_URL]
//   goose examples/client_streams.goose -- https://www.example.com/ https://www.example.com/upload

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

fn main() {
    let a = args();
    guard a.len == 2 || a.len == 3 else { print("usage: client_streams URL [UPLOAD_URL]"); exit(2); }
    let url = a[1];
    let u, ue = http::url_parse(url);
    guard ue == 0 && http::url_check_http(u) == 0 else { print("client_streams: not an http or https URL: ", url); exit(2); }
    var c = http::Client { .. };
    c.opt.timeout_ms = 30000;

    // An upload of 1 MiB made 64 KiB at a time, its length not given
    // (-1): it goes in chunks (HTTP/1.1) or DATA frames (HTTP/2). The
    // block appends the next piece to `out` and says whether more
    // follows; `start` is true when a redirect (307, 308) sends the body
    // again from the beginning, which `rewindable` allows.
    if a.len == 3 {
        let total: i64 = 1 << 20;
        var made: i64     = 0;
        var f:    u8[>..] = [];
        http::add_field(f, "Content-Type", "application/octet-stream");
        var up = http::fetch_stream(c, "PUT", a[2], f, -1, true) { out: u8[>..]&, start: bool =>
            if start { made = 0; }
            let n = min(65536, total - made);
            for i in n { out.push(((made + i) % 251) as! u8); }
            made += n;
            made < total
        };
        guard up.err == http::ERR_NONE else { print("client_streams: upload failed: ", http::client_error_text(up.err)); exit(1); }
        http::read_all(c, up);
        print("PUT ", a[2], ": ", total, " bytes sent, answered ", up.status, " ", http::response_reason(up));
    }

    // A download read as it comes, without keeping the body.
    var r = http::fetch(c, "GET", url, "", "");
    guard r.err == http::ERR_NONE else { print("client_streams: GET failed: ", http::client_error_text(r.err)); exit(1); }
    var piece: u8[>..] = [];
    var total: i64     = 0;
    var pieces = 0;
    while !r.body_done {
        piece.clear();
        let n = http::read_body(c, r, piece);
        guard n >= 0 else { print("client_streams: the body failed: ", http::client_error_text(-n)); exit(1); }
        total += piece.len;
        if piece.len > 0 { pieces++; }
    }
    print("GET ", url, ": ", r.status, ", ", total, " bytes in ", pieces, " reads", if r.h2 { " (HTTP/2)" } else { "" });

    // Three requests begun at once, then their bodies read in turns.
    var r0 = http::begin_request(c, "GET", u, "", 0);
    var r1 = http::begin_request(c, "GET", u, "", 0);
    var r2 = http::begin_request(c, "GET", u, "", 0);
    guard r0.err == 0 && r1.err == 0 && r2.err == 0 else { print("client_streams: a request could not begin"); exit(1); }
    // Each one's head is read by end_request (no body to send here).
    guard http::end_request(c, r0, "") == 0 && http::end_request(c, r1, "") == 0 && http::end_request(c, r2, "") == 0 else {
        print("client_streams: a request failed"); exit(1);
    }
    var b0: u8[>..] = [];
    var b1: u8[>..] = [];
    var b2: u8[>..] = [];
    while !r0.body_done || !r1.body_done || !r2.body_done {
        if !r0.body_done && http::read_body(c, r0, b0) < 0 { print("client_streams: the first body failed"); exit(1); }
        if !r1.body_done && http::read_body(c, r1, b1) < 0 { print("client_streams: the second body failed"); exit(1); }
        if !r2.body_done && http::read_body(c, r2, b2) < 0 { print("client_streams: the third body failed"); exit(1); }
    }
    print("three at once: ", r0.status, "/", r1.status, "/", r2.status, ", ", b0.len, "+", b1.len, "+", b2.len, " bytes, ",
          if r0.h2 && r1.h2 && r2.h2 { "as HTTP/2 streams" } else { "on HTTP/1.1 connections" });
    http::close_idle(c);
}

// h1_conn: an HTTP/1.1 client and server talking over one keep-alive
// connection, in memory. Neither side does I/O: each writes what it would
// send into a buffer, and is handed what arrived, as a program with a
// socket would. The server answers a GET with a fixed length, a POST by
// echoing its chunked body back in chunks, and closes after a request
// that asks it to.
//
//   goose examples/h1_conn.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.h1;
import http.conn1;

// Drops the first n bytes of a buffer (what an event used).
fn drop(buf: u8[>..]&, n: i64) {
    var rest: u8[>..] = [];
    rest.append(buf[n..]);
    buf.clear();
    buf.append(rest);
}

// The server's side: reads what is in `inbox` and answers each request
// that is complete into `wire`.
fn serve(sv: http::ServerConn&, inbox: u8[>..]&, wire: u8[>..]&, body: u8[>..]&, method: u8[>..]&, target: u8[>..]&) {
    var trailer: u8[>..] = [];
    loop {
        let ev, h = http::server_read(sv, inbox, body, trailer, wire);
        if ev.kind == http::EV_REQUEST {
            // The head's spans point into inbox: copy what is needed now.
            method.clear();
            method.append(inbox[h.method.pos..h.method.end]);
            target.clear();
            target.append(inbox[h.target.pos..h.target.end]);
            body.clear();
        }
        drop(inbox, ev.used);
        // Every request ends with EV_END, one without a body too.
        if ev.kind == http::EV_END {
            if method == "GET" {
                let page = "<h1>hello</h1>\n";
                http::server_respond(sv, 200, "Content-Type: text/html\r\n", page.len, wire);
                http::server_body(sv, page, wire);
                http::server_end(sv, "", wire);
            } else {
                http::server_respond(sv, 200, "Content-Type: text/plain\r\n", -1, wire);
                http::server_body(sv, "you sent: ", wire);
                http::server_body(sv, body, wire);
                http::server_end(sv, "", wire);
            }
        }
        if ev.kind == http::EV_ERROR { print("h1_conn: the server failed with ", ev.status); exit(1); }
        // EV_CLOSED: after a response that closes, nothing more is read.
        if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT || ev.kind == http::EV_CLOSED { break; }
    }
}

// The client's side: reads the response in `inbox`; true at its end.
fn receive(cl: http::ClientConn&, inbox: u8[>..]&, body: u8[>..]&, status: i64&) -> bool {
    var trailer: u8[>..] = [];
    loop {
        let ev, h = http::client_read(cl, inbox, body, trailer);
        if ev.kind == http::EV_RESPONSE { status = h.status; }
        drop(inbox, ev.used);
        if ev.kind == http::EV_END { return true; }
        if ev.kind == http::EV_ERROR { print("h1_conn: the client failed"); exit(1); }
        if ev.kind == http::EV_NEED_MORE { return false; }
    }
    return false;
}

fn main() {
    var cl = http::client_conn();
    var sv = http::server_conn(http::server_options());
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var sbody:     u8[>..] = [];
    var method:    u8[>..] = [];
    var target:    u8[>..] = [];

    // 1. GET /, the response read whole.
    http::client_request(cl, "GET", "/", "www.example.com", "Accept: text/html\r\n", 0, to_server);
    serve(sv, to_server, to_client, sbody, method, target);
    var cbody:  u8[>..] = [];
    var status: i64     = 0;
    guard receive(cl, to_client, cbody, status) && status == 200 && cbody == "<h1>hello</h1>\n" else {
        print("h1_conn: GET went wrong"); exit(1);
    }
    print(method, " ", target, " -> ", status, ", ", cbody.len, " bytes; the connection stays open: ", !http::closing(sv));

    // 2. POST in chunks, on the same connection, asking it to close after;
    // the server is given the bytes three at a time.
    var f: u8[>..] = [];
    http::add_field(f, "Connection", "close");
    var post: u8[>..] = [];
    http::client_request(cl, "POST", "/echo", "www.example.com", f, -1, post);
    http::write_chunk(post, "ping ");
    http::write_chunk(post, "pong");
    http::write_last_chunk(post, "");
    var at = 0;
    while at < post.len {
        let n = min(3, post.len - at);
        to_server.append(post[at..at + n]);
        at += n;
        serve(sv, to_server, to_client, sbody, method, target);
    }
    cbody.clear();
    guard receive(cl, to_client, cbody, status) && cbody == "you sent: ping pong" else {
        print("h1_conn: POST came back as '", cbody, "'"); exit(1);
    }
    print(method, " ", target, " -> ", status, ", '", cbody, "'; the server closes now: ", http::closing(sv));
    guard http::closing(sv) && http::client_closed(cl) else { print("h1_conn: Connection: close was not kept"); exit(1); }
}

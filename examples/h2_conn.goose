// h2_conn: an HTTP/2 client and server talking in memory (RFC 9113). The
// two exchange their SETTINGS, then the client opens two streams at once:
// a GET, and a POST of 200 KB that is more than the server's flow-control
// window of 64 KB, so it goes in rounds as the server reads the data and
// gives the window back. The responses come back interleaved on the one
// connection.
//
//   goose examples/h2_conn.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.hpack;
import http.h1;
import http.h2;

// Reads every frame in `inbox`, answering in `wire` (SETTINGS acks,
// WINDOW_UPDATEs as the data is used): the heads to `log`, the data of
// streams 1 and 3 to b1 and b3, and which streams have ended to `ended`.
fn drain(c: http::H2Conn&, inbox: u8[>..]&, wire: u8[>..]&, log: u8[>..]&, b1: u8[>..]&, b3: u8[>..]&, ended: bool[4]&) {
    var fields: u8[>..] = [];
    var data:   u8[>..] = [];
    loop {
        data.clear();
        let ev = http::h2_read(c, inbox, fields, data, wire);
        var rest: u8[>..] = [];
        rest.append(inbox[ev.used..]);
        inbox.clear();
        inbox.append(rest);
        if ev.kind == http::EV2_NEED_MORE { return; }
        if ev.kind == http::EV2_ERROR { print("h2_conn: the connection failed, code ", ev.code); exit(1); }
        if ev.kind == http::EV2_HEADERS {
            // Fields as "name: value" lines, the pseudo-header fields first.
            let path, has_path = http::h2_field(fields, ":path");
            let status, has_status = http::h2_field(fields, ":status");
            if ev.trailers {
                format(log, "  stream ", ev.stream, " trailer: ", fields[..fields.len - 2], "\n");
            } else {
                format(log, "  stream ", ev.stream, ": ", if has_path { path } else { status }, "\n");
            }
        }
        if ev.kind == http::EV2_DATA {
            if ev.stream == 1 { b1.append(data); } else { b3.append(data); }
            http::h2_consumed(c, ev.stream, data.len, wire);    // the window back to the peer
        }
        if (ev.kind == http::EV2_HEADERS || ev.kind == http::EV2_DATA) && ev.end_stream { ended[ev.stream] = true; }
    }
}

fn main() {
    var copt = http::h2_client_options();
    var sopt = http::h2_server_options();
    sopt.stream_window = 65535;
    sopt.conn_window = 65535;
    var cl = http::h2_conn(copt);
    var sv = http::h2_conn(sopt);
    var to_s: u8[>..] = [];
    var to_c: u8[>..] = [];
    // What each side has received: heads, the two streams' data, ends.
    var clog: u8[>..] = [];
    var c1:   u8[>..] = [];
    var c3:   u8[>..] = [];
    var cend: bool[4] = [false; 4];
    var slog: u8[>..] = [];
    var s1:   u8[>..] = [];
    var s3:   u8[>..] = [];
    var send: bool[4] = [false; 4];

    // The preface and SETTINGS each way, and their acknowledgements.
    http::h2_start(cl, to_s);
    http::h2_start(sv, to_c);
    drain(sv, to_s, to_c, slog, s1, s3, send);
    drain(cl, to_c, to_s, clog, c1, c3, cend);
    drain(sv, to_s, to_c, slog, s1, s3, send);

    // Two requests at once: a GET, and a POST whose body is sent as the
    // windows allow.
    let get = http::h2_request(cl, "GET", "https", "www.example.com", "/status", "Accept: text/plain\r\n", true, to_s);
    var upload: u8[>..] = [];
    for i in 200000 { upload.push(((i * 31) % 251) as! u8); }
    let post = http::h2_request(cl, "POST", "https", "www.example.com", "/upload", "Content-Type: application/octet-stream\r\n",
                                false, to_s);
    guard get == 1 && post == 3 else { print("h2_conn: no streams"); exit(1); }
    var sent = 0;
    var rounds = 0;
    var answered_get = false;
    while (sent < upload.len || !send[3]) && rounds < 100 {
        rounds++;
        if sent < upload.len { sent += http::h2_data(cl, post, upload[sent..], true, to_s); }
        drain(sv, to_s, to_c, slog, s1, s3, send);
        // The server answers the GET as soon as it has it.
        if send[1] && !answered_get {
            http::h2_respond(sv, get, 200, "Content-Type: text/plain\r\n", false, to_c);
            http::h2_data(sv, get, "all well\n", true, to_c);
            answered_get = true;
        }
        drain(cl, to_c, to_s, clog, c1, c3, cend);
    }
    guard s3 == upload else { print("h2_conn: the upload came in wrong (", s3.len, " bytes)"); exit(1); }
    print("upload: ", upload.len, " bytes in ", rounds, " rounds of a 64 KB window");

    // The POST's answer, with a trailer section after its data.
    var reply: u8[>..] = [];
    format(reply, "stored ", s3.len, " bytes\n");
    http::h2_respond(sv, post, 201, "Content-Type: text/plain\r\n", false, to_c);
    http::h2_data(sv, post, reply, false, to_c);
    http::h2_trailers(sv, post, "X-Checksum: ok\r\n", to_c);
    drain(cl, to_c, to_s, clog, c1, c3, cend);

    print("server saw:\n", slog, "client saw:\n", clog[..clog.len - 1]);
    guard cend[1] && cend[3] && c1 == "all well\n" && c3 == reply && find(clog, "trailer: x-checksum: ok") > 0 else {
        print("h2_conn: the responses came back wrong"); exit(1);
    }
    print("GET: ", c1, "POST: ", c3, "streams open: ", cl.active + sv.active);
}

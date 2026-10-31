// goose-httpd: an HTTP/1.1 server of static files, over TCP or TLS
// (tlsgoose), for trying the package against real clients.
//
//   goose-httpd --root DIR [--listen 127.0.0.1] [--port 8080]
//               [--cert chain.pem --key key.pem [--tls-max 1.2|1.3]]
//               [--late-ticket]
//
// GET and HEAD serve files under DIR (a directory's index.html); POST
// /echo answers with the request's body; anything else is 405. Paths are
// percent-decoded once, may not hold ".." segments or NUL, and must
// resolve, symbolic links followed, to a file inside DIR. Each connection
// is served by a process of its own; one line a request goes to stderr.
// It listens on 127.0.0.1 unless told otherwise. --late-ticket (for
// tests) sends another TLS 1.3 session ticket a moment after each
// response, when the connection is idle.

import std;
import os;
import http from "..";
import http.conn1;
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import tls from "../../tlsgoose.git";
import tls.handshake;
import sysnet;

let IDLE_MS: i32 = 30000;
let MAX_FILE: i64 = 1 << 28;
var late_ticket = false;

fn die(msg: const u8[:]) {
    write_stderr("goose-httpd: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn pem_der(path: const u8[:], labels: const u8[:][:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die("cannot read a PEM file"); }
    var out: u8[>..] = [];
    for label in labels {
        let ders, ok = asn1::pem_decode(text, label);
        for d in ders { out.append(d); }
        if out.len > 0 { return out; }
    }
    die("no PEM block of the expected kind");
    return out;
}

fn content_type(path: const u8[:]) -> const u8[:] {
    if ends_with(path, ".html") || ends_with(path, ".htm") { return "text/html; charset=utf-8"; }
    if ends_with(path, ".txt") { return "text/plain; charset=utf-8"; }
    if ends_with(path, ".css") { return "text/css"; }
    if ends_with(path, ".js") { return "text/javascript"; }
    if ends_with(path, ".json") { return "application/json"; }
    if ends_with(path, ".png") { return "image/png"; }
    if ends_with(path, ".jpg") || ends_with(path, ".jpeg") { return "image/jpeg"; }
    if ends_with(path, ".svg") { return "image/svg+xml"; }
    return "application/octet-stream";
}

// The request's path, percent-decoded, without its query: "" if it is no
// origin-form path, has a bad escape, a NUL, or a ".." segment.
fn decoded_path(target: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if target.len == 0 || target[0] != '/' { return out; }
    var end = position(target, '?');
    if end < 0 { end = target.len; }
    let hash = position(target, '#');
    if hash >= 0 && hash < end { end = hash; }
    var i = 0;
    while i < end {
        let c = target[i];
        if c == '%' {
            if i + 2 >= end { out.clear(); return out; }
            let a = http::hex_value(target[i + 1]);
            let b = http::hex_value(target[i + 2]);
            if a < 0 || b < 0 { out.clear(); return out; }
            out.push((a * 16 + b) as! u8);
            i += 3;
        } else {
            out.push(c);
            i++;
        }
    }
    var bad = false;
    for c in out { if c == 0 || c == '\\' { bad = true; } }
    each_split(out, '/') { if it == ".." { bad = true; } };
    if bad { out.clear(); }
    return out;
}

struct Answer { status: i64, ctype: u8[..64], extra: u8[..256] }

// The file a GET or HEAD names, into `body`: 200, or 404 or 403.
fn file_answer(root: const u8[:], path: const u8[:], body: u8[>..]&) -> Answer {
    var a = Answer { status: 404, ctype: [], extra: [] };
    var full: u8[>..] = [];
    full.append(root);
    full.append(path);
    if is_dir(full) {
        if !ends_with(path, "/") {
            a.status = 301;
            a.extra.append("Location: ");
            a.extra.append(path);
            a.extra.append("/\r\n");
            return a;
        }
        full.append("index.html");
    }
    let real = sysnet::realpath(full);
    if real.len == 0 { return a; }
    // Inside the root: the root itself, then '/'.
    if real.len <= root.len || real[..root.len] != root || real[root.len] != '/' { a.status = 403; return a; }
    if !file_exists(real) { return a; }
    if !read_file(real, body) { a.status = 403; return a; }
    if body.len > MAX_FILE { body.clear(); a.status = 403; return a; }
    a.status = 200;
    a.ctype.append(content_type(real));
    return a;
}

// Sends `plain` (HTTP bytes) through TLS if there is a connection, then
// all of it to the socket. False if the socket failed.
fn flush(fd: i32, on_tls: bool, tc: tls::Conn&, plain: u8[>..]&, wire: u8[>..]&) -> bool {
    if plain.len > 0 {
        if on_tls { tls::send(tc, plain, wire); } else { wire.append(plain); }
        plain.clear();
    }
    if wire.len > 0 {
        if sysnet::net_write(fd, wire) < 0 { return false; }
        wire.clear();
    }
    return true;
}

// Shut down writing, read what the peer still sends until it closes or a
// second passes, and close: closing with data unread would send a reset
// that can overtake the last response.
fn linger_close(fd: i32) {
    sysnet::net_shutdown_write(fd);
    var sink: u8[>..] = [];
    for k in 20 {
        if sysnet::net_wait(fd, 100) <= 0 { continue; }
        sink.clear();
        if sysnet::read_some(fd, sink) <= 0 { break; }
    }
    sysnet::net_close(fd);
}

fn log(method: const u8[:], target: const u8[:], status: i64, n: i64) {
    var l: u8[>..] = [];
    l.append(method);
    l.push(' ');
    l.append(target);
    l.push(' ');
    format(l, status);
    l.push(' ');
    format(l, n);
    l.push('\n');
    write_stderr(l);
}

fn serve(fd: i32, root: const u8[:], on_tls: bool, scfg: const tls::ServerConfig&) {
    var tc = tls::server(scfg);
    var hc = http::server_conn(http::server_options());
    var raw: u8[>..] = [];
    var buf: u8[>..] = [];
    var plain: u8[>..] = [];
    var wire: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var method: u8[>..] = [];
    var target: u8[>..] = [];
    loop {
        if sysnet::net_wait(fd, IDLE_MS) <= 0 { break; }
        raw.clear();
        if sysnet::read_some(fd, raw) <= 0 { break; }
        // After the client's close_notify nothing more can be sent (and
        // TLS 1.2 discards what is pending), so a request that came with it
        // goes unanswered; the alert or our close_notify goes out as is.
        if on_tls {
            let r = tls::server_feed(tc, scfg, raw, wire, buf);
            if r != 0 || tls::closed(tc) { flush(fd, false, tc, plain, wire); break; }
        } else {
            buf.append(raw);
        }
        var stop = false;
        loop {
            let ev, h = http::server_read(hc, buf, body, trailer, plain);
            if ev.kind == http::EV_REQUEST {
                method.clear();
                method.append(buf[h.method.pos..h.method.end]);
                target.clear();
                target.append(buf[h.target.pos..h.target.end]);
                body.clear();
                trailer.clear();
                if ev.continue_expected { http::server_continue(hc, plain); }
            }
            if ev.kind == http::EV_ERROR {
                log("-", "-", ev.status, 0);
                stop = true;
            }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf.clear();
            buf.append(rest);
            if (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc) {
                answer(hc, root, method, target, body, plain);
                if http::closing(hc) { stop = true; }
            }
            if stop || ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT || ev.kind == http::EV_ERROR { break; }
        }
        if !flush(fd, on_tls, tc, plain, wire) { break; }
        if late_ticket && on_tls && !stop && !http::closing(hc) && tls::version(tc) == tls::VERSION_TLS13 {
            // After the client has had time to read the response.
            sysnet::net_wait(fd, 200);
            if tls::send_session_ticket(tc, scfg, wire) && !flush(fd, false, tc, plain, wire) { break; }
        }
        if stop || http::closing(hc) {
            if on_tls { tls::close(tc, wire); flush(fd, false, tc, plain, wire); }
            break;
        }
    }
    linger_close(fd);
}

fn answer(hc: http::ServerConn&, root: const u8[:], method: const u8[:], target: const u8[:], body: const u8[:], out: u8[>..]&) {
    var f: u8[>..] = [];
    f.append("Server: goose-httpd\r\n");
    var data: u8[>..] = [];
    var status: i64 = 405;
    if method == "POST" && (target == "/echo" || starts_with(target, "/echo?")) {
        status = 200;
        http::add_field(f, "Content-Type", "application/octet-stream");
        data.append(body);
    } else if method == "GET" || method == "HEAD" {
        let path = decoded_path(target);
        if path.len == 0 {
            status = 400;
        } else {
            let a = file_answer(root, path, data);
            status = a.status;
            if a.ctype.len > 0 { http::add_field(f, "Content-Type", a.ctype); }
            f.append(a.extra);
        }
    } else {
        f.append("Allow: GET, HEAD, POST\r\n");
    }
    if status != 200 {
        data.clear();
        data.append(http::reason_phrase(status));
        data.append("\n");
        http::add_field(f, "Content-Type", "text/plain; charset=utf-8");
    }
    http::server_respond(hc, status, f, data.len, out);
    if method != "HEAD" { http::server_body(hc, data, out); }
    http::server_end(hc, "", out);
    log(method, target, status, data.len);
}

fn main() {
    let a = args();
    var root: u8[>..] = [];
    var listen: u8[>..] = [];
    listen.append("127.0.0.1");
    var port: i64 = 8080;
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var tls_max: u8[>..] = [];
    tls_max.append("1.3");
    var i = 1;
    while i < a.len {
        if a[i] == "--late-ticket" { late_ticket = true; i++; continue; }
        if i + 1 >= a.len { die("each option takes a value"); }
        let v = a[i + 1];
        if a[i] == "--root" { root.append(v); }
        else if a[i] == "--listen" { listen.clear(); listen.append(v); }
        else if a[i] == "--port" {
            let n, ok = parse_int(v);
            if !ok || n < 0 || n > 65535 { die("bad --port"); }
            port = n;
        }
        else if a[i] == "--cert" { cert.append(v); }
        else if a[i] == "--key" { key.append(v); }
        else if a[i] == "--tls-max" { tls_max.clear(); tls_max.append(v); }
        else { die("usage: goose-httpd --root DIR [--listen ADDR] [--port N] [--cert chain.pem --key key.pem [--tls-max 1.2|1.3]] [--late-ticket]"); }
        i += 2;
    }
    if root.len == 0 { die("--root is required"); }
    let real_root = sysnet::realpath(root);
    if real_root.len == 0 || !is_dir(real_root) { die("--root is no directory"); }
    let on_tls = cert.len > 0;
    var chain: u8[>..] = [];
    var key_der: u8[>..] = [];
    if on_tls {
        if key.len == 0 { die("--cert needs --key"); }
        chain = pem_der(cert, ["CERTIFICATE"]);
        key_der = pem_der(key, ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"]);
    }
    var scfg, ok = tls::server_config(chain, key_der);
    if on_tls && !ok { die("the certificate and key do not load"); }
    if tls_max == "1.2" { scfg.max_version = tls::VERSION_TLS12; }
    else if tls_max != "1.3" { die("--tls-max is 1.2 or 1.3"); }
    tls::add_alpn(scfg.alpn, "http/1.1");
    sysnet::net_init();
    let lfd = sysnet::net_listen(listen, port as! i32);
    if lfd < 0 { die("cannot listen"); }
    var line: u8[>..] = [];
    line.append("goose-httpd: listening on ");
    line.append(listen);
    line.push(':');
    format(line, sysnet::net_local_port(lfd));
    line.append(if on_tls { " (TLS)\n" } else { "\n" });
    write_stderr(line);
    loop {
        let fd = sysnet::net_accept(lfd);
        sysnet::proc_reap();
        if fd < 0 { continue; }
        let pid = sysnet::proc_fork();
        if pid == 0 {
            sysnet::net_close(lfd);
            serve(fd, real_root, on_tls, scfg);
            sysnet::proc_exit(0);
        }
        sysnet::net_close(fd);
    }
}

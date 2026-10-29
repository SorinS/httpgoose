// goose-http: an HTTP/1.1 client, over TCP or TLS (tlsgoose).
//
//   goose-http [-X METHOD] [-d DATA] [-H 'Name: value'] [-i] [--chunked]
//              [--cacert roots.pem] [--insecure] [--tls-max 1.2|1.3] URL...
//
// Each URL (http:// or https://, host[:port], path) is requested in turn,
// on one connection while they share a scheme, host and port and the
// server keeps it open. The body goes to stdout, the head too with -i.
// Certificates are checked against --cacert, else the system's roots;
// --insecure checks nothing. Exit status: 0, 1 if a request failed, 2 for
// bad arguments.

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

let TIMEOUT_MS: i32 = 30000;

fn die(msg: const u8[:]) {
    write_stderr("goose-http: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn fail(msg: const u8[:]) {
    write_stderr("goose-http: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(1);
}

struct Url { https: bool, port: i64, host: u8[..256], path: u8[..8192] }

// scheme "://" host [":" port] [path], the host a name or a bracketed
// IPv6 address.
fn parse_url(u: const u8[:]) -> Url, bool {
    var r = Url { https: false, port: 80, host: [], path: [] };
    var rest = u[..];
    if starts_with(u, "https://") { r.https = true; r.port = 443; rest = u[8..]; }
    else if starts_with(u, "http://") { rest = u[7..]; }
    else { return r, false; }
    var slash = position(rest, '/');
    if slash < 0 { slash = rest.len; }
    let auth = rest[..slash];
    var hostpart = auth;
    if auth.len > 0 && auth[0] == '[' {
        let close = position(auth, ']');
        if close < 0 { return r, false; }
        hostpart = auth[1..close];
        if close + 1 < auth.len {
            if auth[close + 1] != ':' { return r, false; }
            let p, ok = parse_int(auth[close + 2..]);
            if !ok || p <= 0 || p > 65535 { return r, false; }
            r.port = p;
        }
    } else {
        let colon = position(auth, ':');
        if colon >= 0 {
            hostpart = auth[..colon];
            let p, ok = parse_int(auth[colon + 1..]);
            if !ok || p <= 0 || p > 65535 { return r, false; }
            r.port = p;
        }
    }
    if hostpart.len == 0 || hostpart.len > r.host.cap { return r, false; }
    for c in hostpart { if c <= 0x20 || c >= 0x7f || c == '@' { return r, false; } }
    r.host.append(hostpart);
    if slash < rest.len {
        if rest.len - slash > r.path.cap { return r, false; }
        r.path.append(rest[slash..]);
    } else {
        r.path.push('/');
    }
    return r, true;
}

fn host_field(u: const Url&) -> u8[>..] {
    var h: u8[>..] = [];
    let v6 = position(u.host[..], ':') >= 0;
    if v6 { h.push('['); }
    h.append(u.host[..]);
    if v6 { h.push(']'); }
    if u.port != (if u.https { 443 } else { 80 }) { h.push(':'); format(h, u.port); }
    return h;
}

fn pem_der(path: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die("cannot read --cacert"); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for d in ders { out.append(d); }
    if out.len == 0 { die("no certificate in --cacert"); }
    return out;
}

struct Options {
    method: u8[..32], data: u8[..65536], fields: u8[..16384],
    has_data: bool, include: bool, chunked: bool, insecure: bool, tls12: bool,
    cacert: u8[..4096],
}

fn main() {
    let a = args();
    var o = Options { method: [], data: [], fields: [], has_data: false, include: false, chunked: false,
                      insecure: false, tls12: false, cacert: [] };
    var urls: u8[>..] = [];       // NUL-separated
    var i = 1;
    while i < a.len {
        let s = a[i];
        let has_next = i + 1 < a.len;
        if s == "-X" && has_next { o.method.clear(); o.method.append(a[i + 1]); i += 2; }
        else if s == "-d" && has_next {
            if a[i + 1].len > o.data.cap { die("-d: at most 64 KiB"); }
            o.data.append(a[i + 1]); o.has_data = true; i += 2;
        }
        else if s == "-H" && has_next {
            let h = a[i + 1];
            let colon = position(h, ':');
            if colon <= 0 { die("-H takes 'Name: value'"); }
            var f: u8[>..] = [];
            if !http::add_field(f, h[..colon], http::trim_ows(h[colon + 1..])) { die("-H: not a valid field"); }
            if o.fields.len + f.len > o.fields.cap { die("-H: too many fields"); }
            o.fields.append(f);
            i += 2;
        }
        else if s == "-i" { o.include = true; i++; }
        else if s == "--chunked" { o.chunked = true; i++; }
        else if s == "--insecure" { o.insecure = true; i++; }
        else if s == "--cacert" && has_next { o.cacert.append(a[i + 1]); i += 2; }
        else if s == "--tls-max" && has_next {
            if a[i + 1] == "1.2" { o.tls12 = true; } else if a[i + 1] != "1.3" { die("--tls-max is 1.2 or 1.3"); }
            i += 2;
        }
        else if starts_with(s, "-") { die("usage: goose-http [-X METHOD] [-d DATA] [-H 'N: v'] [-i] [--chunked] [--cacert F] [--insecure] [--tls-max 1.2|1.3] URL..."); }
        else { urls.append(s); urls.push(0); i++; }
    }
    if urls.len == 0 { die("no URL"); }
    if o.method.len == 0 { o.method.append(if o.has_data { "POST" } else { "GET" }); }
    sysnet::net_init();
    var roots: u8[>..] = [];
    if o.cacert.len > 0 { roots = pem_der(o.cacert[..]); }
    var status = 0;
    // One connection while the URLs share an origin.
    var fd: i32 = -1;
    var cur = Url { https: false, port: 0, host: [], path: [] };
    var ccfg = tls::client_config("", "");
    var tc = tls::client(ccfg);
    var hc = http::client_conn();
    var raw: u8[>..] = [];
    var buf: u8[>..] = [];
    var wire: u8[>..] = [];
    var plain: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    each_split(urls, 0) {
        let us = it;
        if us.len > 0 {
            let u, ok = parse_url(us);
            if !ok { die("not an http or https URL"); }
            let same = fd >= 0 && u.https == cur.https && u.port == cur.port && u.host[..] == cur.host[..] &&
                       !http::client_closed(hc);
            if !same {
                if fd >= 0 { sysnet::net_close(fd); }
                cur = u;
                fd = sysnet::net_connect(u.host[..], u.port as! i32);
                if fd < 0 { fail("cannot connect"); }
                hc = http::client_conn();
                buf.clear();
                if u.https {
                    ccfg = tls::client_config(u.host[..], roots);
                    ccfg.system_roots = roots.len == 0;
                    ccfg.verify = !o.insecure;
                    if o.tls12 { ccfg.max_version = tls::VERSION_TLS12; }
                    tls::add_alpn(ccfg.alpn, "http/1.1");
                    tc = tls::client(ccfg);
                    wire.clear();
                    tls::client_start(tc, ccfg, wire);
                    while !tls::connected(tc) {
                        if sysnet::net_write(fd, wire) < 0 { fail("write failed"); }
                        wire.clear();
                        if sysnet::net_wait(fd, TIMEOUT_MS) <= 0 { fail("TLS handshake timed out"); }
                        raw.clear();
                        if sysnet::read_some(fd, raw) <= 0 { fail("the server closed during the TLS handshake"); }
                        if tls::client_feed(tc, ccfg, raw, wire, buf) != 0 {
                            sysnet::net_write(fd, wire);
                            fail("the TLS handshake failed");
                        }
                    }
                    if sysnet::net_write(fd, wire) < 0 { fail("write failed"); }
                    wire.clear();
                }
            }
            let length: i64 = if o.chunked { -1 } else { o.data.len };
            if !http::client_request(hc, o.method[..], u.path[..], host_field(u), o.fields[..], length, plain) {
                die("the request cannot be written");
            }
            if o.chunked {
                http::write_chunk(plain, o.data[..]);
                http::write_last_chunk(plain, "");
            } else {
                plain.append(o.data[..]);
            }
            if u.https { tls::send(tc, plain, wire); } else { wire.append(plain); }
            plain.clear();
            if sysnet::net_write(fd, wire) < 0 { fail("write failed"); }
            wire.clear();
            body.clear();
            var done = false;
            var final_status: i64 = 0;
            // The peer closed: acted on once what arrived before it is read,
            // as a response and TLS's close_notify can come in one read.
            var peer_closed = false;
            while !done {
                let ev, h = http::client_read(hc, buf, body, trailer);
                if ev.kind == http::EV_RESPONSE {
                    if h.status >= 200 { final_status = h.status; }
                    if o.include { write_stdout(buf[..ev.used]); }
                }
                var rest: u8[>..] = [];
                rest.append(buf[ev.used..]);
                buf.clear();
                buf.append(rest);
                if ev.kind == http::EV_ERROR { fail("the response could not be read"); }
                if ev.kind == http::EV_END || (ev.kind == http::EV_RESPONSE && (http::client_idle(hc) || http::client_closed(hc))) {
                    done = true;
                    break;
                }
                if ev.kind == http::EV_NEED_MORE {
                    if peer_closed {
                        let e = http::client_eof(hc);
                        if e.kind == http::EV_END { done = true; break; }
                        fail("the server closed the connection");
                    }
                    if sysnet::net_wait(fd, TIMEOUT_MS) <= 0 { fail("the response timed out"); }
                    raw.clear();
                    let n = sysnet::read_some(fd, raw);
                    if n <= 0 {
                        peer_closed = true;
                    } else if u.https {
                        if tls::client_feed(tc, ccfg, raw, wire, buf) != 0 { fail("TLS failed"); }
                        if wire.len > 0 { sysnet::net_write(fd, wire); wire.clear(); }
                        if tls::closed(tc) { peer_closed = true; }
                    } else {
                        buf.append(raw);
                    }
                }
            }
            write_stdout(body);
            if final_status >= 400 { status = 1; }
        }
    };
    flush_stdout();
    if fd >= 0 {
        if cur.https && tls::connected(tc) { wire.clear(); tls::close(tc, wire); sysnet::net_write(fd, wire); }
        sysnet::net_close(fd);
    }
    exit(status);
}

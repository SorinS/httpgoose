// goose-http: an HTTP/1.1 client on http.fetch, with curl's options.
//
//   goose-http [options] URL...
//
//   -X METHOD           the method (default GET, or POST with -d)
//   -d DATA, -d @FILE   a body (--data-binary the same; "-" or @- reads stdin)
//   -T FILE             upload FILE ("-": stdin) with PUT, read as it is sent, in
//                       chunks if its size is not known; to URL/FILE's name if
//                       the URL ends in "/". Expect: 100-continue goes with it
//                       over 1 MiB or of unknown size (-H 'Expect:' for none)
//   --expect100-timeout S   how long to wait for the 100 (default 1)
//   --chunked           send the body in chunks
//   -H 'Name: value'    a request field
//   -A AGENT, -e URL    User-Agent, Referer
//   -i                  write the response head too; -I: HEAD, the head only
//   -o FILE             write bodies to FILE
//   -L                  follow redirects (at most --max-redirs N, default 50 as curl)
//   -u USER:PASSWORD    credentials: --basic (sent at once, the default), or
//                       --digest / --anyauth (in answer to a 401)
//   --oauth2-bearer T   Authorization: Bearer T
//   -x URL              a proxy (http, https, socks5, socks5h; userinfo for its
//                       credentials); else HTTP_PROXY, HTTPS_PROXY and NO_PROXY
//   --noproxy LIST      hosts that go direct
//   -b FILE             cookies to send, from a cookies.txt (-b '' turns cookies on)
//   -c FILE             the cookies at the end, written to a cookies.txt
//   --compressed        ask for gzip and decode it
//   --cacert FILE       trust these roots (PEM), not the system's; -k checks nothing
//   --tls-max 1.2|1.3   the highest TLS version
//   --http1.1           HTTP/1.1 only (HTTP/2 is offered over TLS by default);
//   --http2-prior-knowledge   HTTP/2 over TCP too, without asking
//   --connect-timeout S, -m S   seconds to connect, for the whole of each request
//   --rate N/s|N/m|N/h  start at most N requests a second, minute or hour
//   -s                  print no errors; -v: say what happens on stderr
//
// URLs are fetched in turn on one client, so connections to one origin are
// kept and used again. Exit status: 0; 1 if a request failed or got a
// status of 400 or more; 2 for bad arguments.

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

extern fn upfile_open(path: const u8[:]) -> i64;
extern fn upfile_size(fd: i64) -> i64;
extern fn upfile_read(fd: i64, buf: u8[:]) -> i64;
extern fn upfile_rewind(fd: i64) -> bool;
extern fn upfile_close(fd: i64);

var silent = false;
var verbose = false;

fn die(msg: const u8[:]) {
    write_stderr("goose-http: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn say(a: const u8[:], b: const u8[:]) {
    if silent { return; }
    write_stderr("goose-http: ");
    write_stderr(a);
    write_stderr(b);
    write_stderr("\n");
}

fn note(a: const u8[:], b: const u8[:]) {
    if !verbose { return; }
    write_stderr("* ");
    write_stderr(a);
    write_stderr(b);
    write_stderr("\n");
}

fn seconds_ms(s: const u8[:]) -> i64 {
    let v, ok = parse_flt(s);
    if !ok || v < 0.0 { die("a time is seconds"); }
    return (v * 1000.0) as! i64;
}

fn read_data(arg: const u8[:], out: u8[>..]&) {
    if arg == "-" || arg == "@-" { read_stdin(out); return; }
    if arg.len > 0 && arg[0] == '@' {
        if !read_file(arg[1..], out) { die("cannot read the data file"); }
        return;
    }
    out.append(arg);
}

// The file read as it is sent: -T.
fn upload_to(c: http::Client&, method: const u8[:], url: const u8[:], fields: const u8[:], path: const u8[:], no_expect: bool) -> http::Response {
    let fd = upfile_open(path);
    if fd < 0 { die("cannot read the -T file"); }
    let size = upfile_size(fd);
    // A URL ending in "/" gets the file's name, as curl does.
    var target: u8[>..] = [];
    target.append(url);
    let q = position(url, '?');
    let path_end = if q < 0 { url.len } else { q };
    if path != "-" && path_end > 0 && url[path_end - 1] == '/' {
        target.resize(path_end);
        let slash = http::last_index(path, '/');
        http::path_escape(target, path[slash + 1..]);
        target.append(url[path_end..]);
    }
    var f: u8[>..] = [];
    f.append(fields);
    if !no_expect && (size < 0 || size > (1 << 20)) && !http::has_field(f, "Expect") {
        http::add_field(f, "Expect", "100-continue");
    }
    var failed = false;
    // A file is read again for a hop that sends it again (curl rewinds it
    // too); standard input cannot be.
    var r = http::fetch_stream(c, method, target, f, size, size >= 0) { out: u8[>..]&, start: bool =>
        if start && size >= 0 && !upfile_rewind(fd) { failed = true; }
        let at = out.len;
        out.resize(at + 65536, 0);
        let n = if failed { -1 } else { upfile_read(fd, out[at..]) };
        if n < 0 { failed = true; out.resize(at); false } else { out.resize(at + n); n > 0 }
    };
    upfile_close(fd);
    if failed { die("reading the -T file failed"); }
    return r;
}

fn main() {
    let a = args();
    var c = http::Client { .. };
    c.opt.compression = false;          // curl asks for gzip only with --compressed
    c.opt.follow_redirects = false;     // and follows redirects only with -L
    c.opt.max_redirects = 50;
    c.opt.auth = http::AUTH_BASIC;
    var method: u8[>..] = [];
    var data: u8[>..] = [];
    var has_data = false;
    var fields: u8[>..] = [];
    var include = false;
    var head_only = false;
    var out_file: u8[>..] = [];
    var proxy: u8[>..] = [];
    var has_proxy = false;
    var no_proxy: u8[>..] = [];
    var cookie_in: u8[>..] = [];
    var cookies_on = false;
    var cookie_out: u8[>..] = [];
    var cacert: u8[>..] = [];
    var tls12 = false;
    var interval_ms: i64 = 0;
    var upload: u8[>..] = [];
    var no_expect = false;
    var urls: u8[>..] = [];             // NUL-separated
    var i = 1;
    while i < a.len {
        let s = a[i];
        let has_next = i + 1 < a.len;
        let next = if has_next { a[i + 1] } else { "" };
        if s == "-X" && has_next { method.clear(); method.append(next); i += 2; }
        else if (s == "-d" || s == "--data" || s == "--data-binary") && has_next {
            read_data(next, data);
            has_data = true;
            i += 2;
        }
        else if (s == "-T" || s == "--upload-file") && has_next { upload.clear(); upload.append(next); i += 2; }
        else if s == "--expect100-timeout" && has_next { c.opt.expect_continue_ms = seconds_ms(next); i += 2; }
        else if s == "--chunked" { http::add_field(fields, "Transfer-Encoding", "chunked"); i++; }
        else if s == "-H" && has_next {
            let colon = position(next, ':');
            if colon <= 0 { die("-H takes 'Name: value'"); }
            // "Expect:" with nothing after it: no Expect (curl's way to drop a field it adds).
            if http::eq_fold(next[..colon], "Expect") && http::trim_ows(next[colon + 1..]).len == 0 { no_expect = true; i += 2; continue; }
            if !http::add_field(fields, next[..colon], http::trim_ows(next[colon + 1..])) { die("-H: not a valid field"); }
            i += 2;
        }
        else if s == "-A" && has_next { c.opt.user_agent.clear(); c.opt.user_agent.append(next); i += 2; }
        else if s == "-e" && has_next {
            if !http::add_field(fields, "Referer", next) { die("-e: not a valid field value"); }
            i += 2;
        }
        else if s == "-i" { include = true; i++; }
        else if s == "-I" { head_only = true; include = true; i++; }
        else if s == "-o" && has_next { out_file.clear(); out_file.append(next); i += 2; }
        else if s == "-L" { c.opt.follow_redirects = true; i++; }
        else if s == "--max-redirs" && has_next {
            let n, ok = parse_int(next);
            if !ok { die("--max-redirs takes a number"); }
            c.opt.max_redirects = if n < 0 { 1 << 30 } else { n };
            i += 2;
        }
        else if s == "-u" && has_next {
            let colon = position(next, ':');
            if colon < 0 { http::set_credentials(c, next, ""); } else { http::set_credentials(c, next[..colon], next[colon + 1..]); }
            i += 2;
        }
        else if s == "--basic" { c.opt.auth = http::AUTH_BASIC; i++; }
        else if s == "--digest" { c.opt.auth = http::AUTH_DIGEST; i++; }
        else if s == "--anyauth" { c.opt.auth = http::AUTH_ANY; i++; }
        else if s == "--oauth2-bearer" && has_next { http::set_bearer(c, next); i += 2; }
        else if (s == "-x" || s == "--proxy") && has_next { proxy.clear(); proxy.append(next); has_proxy = true; i += 2; }
        else if s == "--noproxy" && has_next { no_proxy.clear(); no_proxy.append(next); i += 2; }
        else if s == "-b" && has_next { cookie_in.clear(); cookie_in.append(next); cookies_on = true; i += 2; }
        else if s == "-c" && has_next { cookie_out.clear(); cookie_out.append(next); cookies_on = true; i += 2; }
        else if s == "--http1.1" { c.opt.http2 = false; i++; }
        else if s == "--http2" { c.opt.http2 = true; i++; }
        else if s == "--http2-prior-knowledge" { c.opt.h2c = true; i++; }
        else if s == "--compressed" { c.opt.compression = true; i++; }
        else if s == "--cacert" && has_next { cacert.clear(); cacert.append(next); i += 2; }
        else if s == "-k" || s == "--insecure" { c.opt.insecure = true; i++; }
        else if s == "--tls-max" && has_next {
            if next == "1.2" { tls12 = true; } else if next != "1.3" { die("--tls-max is 1.2 or 1.3"); }
            i += 2;
        }
        else if s == "--connect-timeout" && has_next { c.opt.connect_timeout_ms = seconds_ms(next); i += 2; }
        else if (s == "-m" || s == "--max-time") && has_next { c.opt.timeout_ms = seconds_ms(next); i += 2; }
        else if s == "--rate" && has_next {
            let slash = position(next, '/');
            let n, ok = parse_int(if slash < 0 { next } else { next[..slash] });
            let unit = if slash < 0 { "h" } else { next[slash + 1..] };
            let per: i64 = if unit == "s" { 1000 } else if unit == "m" { 60000 } else if unit == "h" { 3600000 } else { 0 };
            if !ok || n <= 0 || per == 0 { die("--rate is N/s, N/m or N/h"); }
            interval_ms = per / n;
            i += 2;
        }
        else if s == "-s" || s == "--silent" { silent = true; i++; }
        else if s == "-v" || s == "--verbose" { verbose = true; i++; }
        else if s.len > 1 && s[0] == '-' { die("unknown option; see the comment at the top of tools/http.goose"); }
        else { urls.append(s); urls.push(0); i++; }
    }
    if urls.len == 0 { die("no URL"); }
    if method.len == 0 { method.append(if head_only { "HEAD" } else if upload.len > 0 { "PUT" } else if has_data { "POST" } else { "GET" }); }
    if upload.len > 0 && has_data { die("-T and -d do not go together"); }
    if has_data && !head_only {
        let ct, has_ct = http::field_value(fields, "Content-Type");
        if !has_ct { http::add_field(fields, "Content-Type", "application/x-www-form-urlencoded"); }
    }
    if cacert.len > 0 {
        var text: u8[>..] = [];
        if !read_file(cacert, text) { die("cannot read --cacert"); }
        let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
        var der: u8[>..] = [];
        for d in ders { der.append(d); }
        if !http::set_roots_der(c, der) { die("no certificate in --cacert"); }
    }
    if tls12 { c.tlscfg.max_version = tls::VERSION_TLS12; }
    if has_proxy {
        if !http::set_proxy(c, proxy, no_proxy) { die("-x: not an http, https, socks5 or socks5h URL"); }
    } else {
        http::proxy_from_environment(c);
        if no_proxy.len > 0 { c.no_proxy.clear(); c.no_proxy.append(no_proxy); }
    }
    if cookies_on {
        http::enable_cookies(c);
        if cookie_in.len > 0 {
            var text: u8[>..] = [];
            if read_file(cookie_in, text) { http::jar_load_netscape(c.jar, c.psl, text, http::wall_ms()); }
        }
    }
    var status = 0;
    var out: u8[>..] = [];
    var last_start: i64 = -1;
    each_split(urls, 0) {
        let us = it;
        if us.len > 0 {
            if interval_ms > 0 {
                let now = clock_ns() / 1000000;
                if last_start >= 0 && now < last_start + interval_ms { sleep_ms(last_start + interval_ms - now); }
                last_start = clock_ns() / 1000000;
            }
            var r = if upload.len > 0 { upload_to(c, method, us, fields, upload, no_expect) } else { http::fetch(c, method, us, fields, data) };
            if r.err != http::ERR_NONE {
                if r.err == http::ERR_REDIRECTS { say("too many redirects at ", http::response_url(r)); }
                else { say(http::client_error_text(r.err), if r.status > 0 { " (the proxy answered with a refusal)" } else { "" }); }
                status = 1;
            } else {
                note("from ", http::response_url(r));
                if r.h2 { note("HTTP/2, stream ", str(r.stream)); }
                note(if r.reused { "connection reused" } else { "new connection" },
                     if r.tls_version == tls::VERSION_TLS13 { ", TLS 1.3" } else if r.tls_version == tls::VERSION_TLS12 { ", TLS 1.2" } else { "" });
                if r.tls_resumed { note("TLS session resumed", ""); }
                if include {
                    if r.h2 {
                        out.append("HTTP/2 ");
                        format(out, r.status);
                    } else {
                        out.append("HTTP/1.");
                        format(out, r.minor);
                        out.push(' ');
                        format(out, r.status);
                        out.push(' ');
                        out.append(http::response_reason(r));
                    }
                    out.append("\r\n");
                    out.append(http::response_fields(r));
                    out.append("\r\n");
                }
                // The body, written as it comes.
                var chunk: u8[>..] = [];
                while !r.body_done {
                    chunk.clear();
                    let n = http::read_body(c, r, chunk);
                    if n < 0 { say(http::client_error_text(-n), ""); status = 1; break; }
                    if !head_only { out.append(chunk); }
                    if out.len > (1 << 20) {
                        if out_file.len > 0 { append_file(out_file, out); } else { write_stdout(out); }
                        out.clear();
                    }
                }
                if r.status >= 400 { status = 1; }
            }
        }
    };
    if out_file.len > 0 {
        if !append_file(out_file, out) { say("cannot write ", out_file); status = 1; }
    } else {
        write_stdout(out);
    }
    flush_stdout();
    if cookie_out.len > 0 {
        var text: u8[>..] = [];
        http::jar_save_netscape(c.jar, text, http::wall_ms(), true);
        if !write_file(cookie_out, text) { say("cannot write ", cookie_out); status = 1; }
    }
    http::close_idle(c);
    exit(status);
}

// h1_messages: HTTP/1.1 messages as bytes (RFC 9112), with no connection.
// A request is written and parsed back, its fields read and its body's
// framing found; a response with a chunked body and a trailer is written
// and decoded as it would arrive, in pieces; and requests built to
// smuggle a second one past a proxy are refused.
//
//   goose examples/h1_messages.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.h1;

fn main() {
    let lim = http::default_limits();

    // A request: fields checked as they are added (no CR or LF can get
    // into one), then the head, then a body of Content-Length bytes.
    var f: u8[>..] = [];
    http::add_field(f, "Host", "api.example.com");
    http::add_field(f, "Content-Type", "application/json");
    guard !http::add_field(f, "X-Note", "a\r\nInjected: yes") else { print("h1: a CRLF got into a field"); exit(1); }
    let body = "{\"name\":\"widget\",\"count\":3}";
    http::add_content_length(f, body.len);
    var req: u8[>..] = [];
    guard http::write_request_head(req, "POST", "/v1/items?draft=1", f) else { print("h1: the head was refused"); exit(1); }
    req.append(body);

    // A server reads it: the head's length, then what it says.
    let h, n = http::parse_request(req, lim);
    guard n > 0 && http::check_request(req, h) == 0 else { print("h1: the request does not parse: ", n); exit(1); }
    let fr, e = http::request_framing(req, h);
    guard e == 0 && fr.kind == http::BODY_LENGTH && req[n..n + fr.length] == body else { print("h1: the body is misframed"); exit(1); }
    let ct, has_ct = http::get(req, h, "content-type");
    guard has_ct else { print("h1: no Content-Type"); exit(1); }
    print(req[h.method.pos..h.method.end], " ", req[h.target.pos..h.target.end], " HTTP/1.", h.minor, ": ",
          h.fields.len, " fields, ", req[ct.pos..ct.end], ", a body of ", fr.length, " bytes");

    // Half a head is not an error: more bytes are needed.
    let h2, n2 = http::parse_request(req[..20], lim);
    guard n2 == http::NEED_MORE else { print("h1: half a head was taken"); exit(1); }

    // A response in chunks, with a trailer after the body.
    var tr: u8[>..] = [];
    http::add_field(tr, "X-Checksum", "9f2c");
    var resp: u8[>..] = [];
    http::write_response_head(resp, http::STATUS_CREATED, "Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n");
    http::write_chunk(resp, "created ");
    http::write_chunk(resp, "item 42\n");
    http::write_last_chunk(resp, tr);

    // A client reads it as it comes: the head, then the body 7 bytes at
    // a time through a chunked decoder.
    let rh, rn = http::parse_response(resp, lim);
    let rf, re = http::response_framing(resp, rh, false, false);
    guard rn > 0 && re == 0 && rf.kind == http::BODY_CHUNKED else { print("h1: the response is misframed"); exit(1); }
    var d = http::chunked_decoder();
    var got:     u8[>..] = [];
    var trailer: u8[>..] = [];
    var p = rn;
    while p < resp.len && !http::chunked_done(d) {
        let end = min(p + 7, resp.len);
        let used = http::chunked_feed(d, lim, resp[p..end], got, trailer);
        guard used >= 0 else { print("h1: bad chunks"); exit(1); }
        p += used;
    }
    guard http::chunked_done(d) && got == "created item 42\n" && trailer == "X-Checksum: 9f2c\r\n" else {
        print("h1: the chunked body came back as '", got, "'"); exit(1);
    }
    print(rh.status, " ", resp[rh.reason.pos..rh.reason.end], ": ", got.len, " bytes in chunks, trailer ", trailer[..trailer.len - 2]);

    // Request smuggling: framings two parsers could read two ways. Each is
    // refused with the status to answer (as a negative number).
    let smuggled = [
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 40\r\n\r\nabcd",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
        "GET / HTTP/1.1\nHost: a\n\n",
    ];
    let why = ["Content-Length and Transfer-Encoding", "two Content-Lengths", "a space before the colon", "bare LF line ends"];
    for i in smuggled.len {
        let m = smuggled[i];
        let sh, sn = http::parse_request(m, lim);
        var status = sn;
        if sn > 0 { status = http::check_request(m, sh); }
        if status >= 0 {
            let sf, se = http::request_framing(m, sh);
            status = se;
        }
        guard status < 0 else { print("h1: taken: ", m); exit(1); }
        print("refused with ", -status, ": ", why[i]);
    }
}

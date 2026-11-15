// content_coding: decoding a response body sent with Content-Encoding
// gzip or deflate (RFC 9110 §8.4.1) as it arrives, a piece at a time,
// with no need to hold the compressed body whole. The bodies are made
// here with gslib's compress; a server's would come off the socket.
// A body cut short, or changed on the way, is caught.
//
//   goose examples/content_coding.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import compress from "SorinS/compressgoose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import compress.gzip;
import compress.zlib;
import compress.deflate;
import http.flate;

// Feeds `body` to a decoder in pieces of `piece` bytes, as reads of a
// socket would give it: the decoded bytes, the error (0 for none), and
// whether the stream ended whole.
fn decode(coding: const u8[:], body: const u8[:], piece: i64) -> u8[>..], i64, bool {
    // "deflate" in HTTP is zlib's format; a raw DEFLATE stream is taken too.
    var d = if coding == "gzip" { http::gzip_decoder() } else { http::deflate_decoder() };
    var out: u8[>..] = [];
    var p = 0;
    var e: i64 = 0;
    while p < body.len && e == 0 {
        let n = min(piece, body.len - p);
        e = http::inflate_feed(d, body[p..p + n], out);
        p += n;
    }
    return out, e, http::inflate_done(d);
}

fn main() {
    // A page, as a server would compress it.
    var page: u8[>..] = [];
    for i in 2000 { format(page, "<li>item ", i, " of the catalogue</li>\n"); }
    var gz:  u8[>..] = [];
    var zl:  u8[>..] = [];
    var raw: u8[>..] = [];
    guard compress::gzip_encode(page, gz) == 0 && compress::zlib_encode(page, zl) == 0 &&
          compress::deflate_encode(page, raw) == 0 else { print("content_coding: cannot compress"); exit(1); }

    let codings = ["gzip", "deflate", "deflate"];
    let names = ["gzip", "deflate (zlib)", "deflate (raw)"];
    for i in 3 {
        let body = if i == 0 { gz[..] } else if i == 1 { zl[..] } else { raw[..] };
        let out, e, whole = decode(codings[i], body, 1460);
        guard e == 0 && whole && out == page else { print("content_coding: ", names[i], " failed: ", e); exit(1); }
        print(names[i], ": ", body.len, " bytes on the wire, ", out.len, " decoded, in pieces of 1460");
    }

    // Two gzip members one after the other are one body (as Go reads it).
    var two: u8[>..] = [];
    compress::gzip_encode("first part, ", two);
    compress::gzip_encode("second part", two);
    let both, e2, whole2 = decode("gzip", two, 7);
    guard e2 == 0 && whole2 && both == "first part, second part" else { print("content_coding: two members"); exit(1); }
    print("two gzip members: ", both);

    // A body cut short: no error yet, but the stream is not whole, and
    // the client must not take it as the page.
    let cut, e3, whole3 = decode("gzip", gz[..gz.len / 2], 1460);
    guard e3 == 0 && !whole3 else { print("content_coding: a cut body was taken"); exit(1); }
    print("cut short: ", cut.len, " bytes decoded, not whole");

    // A byte changed in the gzip trailer's CRC-32: an error.
    var bad: u8[>..] = [];
    bad.append(gz);
    bad[bad.len - 8] ^= 0x01;
    let x, e4, whole4 = decode("gzip", bad, 1460);
    guard e4 == http::FLATE_ERR_CHECK else { print("content_coding: a bad CRC was taken"); exit(1); }
    print("changed on the way: refused (", e4, ", the CRC-32 does not match)");
}

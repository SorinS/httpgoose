// hpack: HTTP/2's header compression (RFC 7541). An encoder and a decoder,
// one for each end of a connection, carry three requests' header lists;
// the encoder's dynamic table makes each request after the first a few
// bytes, and a field marked sensitive (a cookie, a password) is never
// put in a table. The peer then lowers its table size, and the next block
// says so first.
//
//   goose examples/hpack.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.hpack;

// A header list as "name: value" lines; a "!" before the name marks it
// sensitive.
fn encode(t: http::HpackTable&, lines: const u8[:][:], out: u8[>..]&) {
    http::hpack_begin(t, out);
    for l in lines {
        let colon = position(l, ':');
        let sensitive = l[0] == '!';
        let name = if sensitive { l[1..colon] } else { l[..colon] };
        http::hpack_field(t, out, name, l[colon + 2..], sensitive);
    }
}

// Decodes a block and checks it gives back `lines`.
fn decode(t: http::HpackTable&, blk: const u8[:], lines: const u8[:][:]) {
    var recs: u8[>..] = [];
    let e = http::hpack_decode(t, blk, 65536, recs);
    guard e == http::HPACK_OK else { print("hpack: the block does not decode: ", e); exit(1); }
    var k = 0;
    http::each_hpack_field(recs) { name, value, sensitive =>
        guard k < lines.len else { print("hpack: more fields than were sent"); exit(1); }
        let want = lines[k];
        let colon = position(want, ':');
        let n = if want[0] == '!' { want[1..colon] } else { want[..colon] };
        guard name == n && value == want[colon + 2..] && sensitive == (want[0] == '!') else {
            print("hpack: field ", k, " came back as ", name, ": ", value); exit(1);
        }
        k++;
    };
    guard k == lines.len else { print("hpack: ", k, " fields of ", lines.len); exit(1); }
}

fn main() {
    // Each end: the encoder's table sized by the peer's limit, the
    // decoder's by our own (4096 unless SETTINGS say otherwise).
    var enc = http::hpack_table(4096);
    var dec = http::hpack_table(4096);
    let pages = ["/", "/style.css", "/app.js"];
    for path in pages {
        let path_line = str(":path: ", path);
        let lines = [":method: GET", ":scheme: https", ":authority: www.example.com", path_line,
                     "user-agent: example-browser/1.0", "accept-language: en-GB,en;q=0.8",
                     "!cookie: session=4f6e1c2a9b"];
        var plain = 0;
        for l in lines { plain += l.len + 2; }
        var blk: u8[>..] = [];
        encode(enc, lines, blk);
        decode(dec, blk, lines);
        print(path, ": ", plain, " bytes of fields, a block of ", blk.len, "; the table holds ", enc.count, " entries");
    }
    guard enc.count == dec.count else { print("hpack: the tables are out of step"); exit(1); }

    // The decoder's side advertises a table of 256 bytes
    // (SETTINGS_HEADER_TABLE_SIZE): the encoder evicts, and its next
    // block starts with a size update.
    http::hpack_peer_limit(enc, 256);
    var blk: u8[>..] = [];
    let last = [":method: GET", ":path: /favicon.ico", ":authority: www.example.com"];
    encode(enc, last, blk);
    guard (blk[0] & 0xe0) == 0x20 else { print("hpack: no size update"); exit(1); }
    decode(dec, blk, last);
    print("after a size update to 256: ", enc.count, " entries, ", enc.size, " bytes");

    // Huffman coding alone (§5.2), as string literals use it.
    var h: u8[>..] = [];
    http::huffman_encode(h, "www.example.com");
    var back: u8[>..] = [];
    guard http::huffman_decode(h, back) && back == "www.example.com" else { print("hpack: Huffman"); exit(1); }
    print("Huffman: 15 bytes in ", h.len);
}

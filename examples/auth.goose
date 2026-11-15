// auth: answering a 401. The WWW-Authenticate field is read into its
// challenges, the strongest scheme offered is picked (Digest before
// Basic), and the Authorization field is made for it; Basic and Bearer
// too. The Digest answer is RFC 7616 §3.9.1's example, so the result is
// known.
//
//   goose examples/auth.goose

import std;
import http from "..";
import net from "SorinS/netgoose@v0.7.0";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509 from "SorinS/x509goose@v0.7.0";
import tls from "SorinS/tlsgoose@v0.7.0";
import ntlm from "SorinS/ntlmgoose@v0.7.0";
import http.auth;

fn main() {
    // A server offering two schemes in one field.
    let www = str("Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, ",
                  "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", ",
                  "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", Basic realm=\"http-auth@example.org\"");
    var digest: u8[>..] = [];
    var has_digest = false;
    var schemes = 0;
    http::each_challenge(www) { scheme, params =>
        let realm, ok = http::auth_param(params, "realm");
        print("challenge: ", scheme, ", realm ", realm);
        schemes++;
        if http::eq_fold(scheme, "Digest") && !has_digest {
            digest.append(params);
            has_digest = true;
        }
    };
    guard schemes == 2 && has_digest else { print("auth: the challenges were misread"); exit(1); }
    let alg, ok = http::auth_param(digest, "algorithm");
    print("digest algorithm: ", alg);

    // The answer for GET /dir/index.html, the first request with this
    // nonce (nc 1). The cnonce is fixed here to get RFC 7616's answer; ""
    // makes a random one, as a client should.
    var a: u8[>..] = [];
    guard http::digest_credentials(a, digest, "Mufasa", "Circle of Life", "GET", "/dir/index.html", "", 1,
                                   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ") else {
        print("auth: the challenge cannot be answered"); exit(1);
    }
    print("Authorization: ", a);
    guard find(a, "response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\"") > 0 else {
        print("auth: not RFC 7616's response"); exit(1);
    }

    // A random cnonce: the same challenge, another response each time.
    var r1: u8[>..] = [];
    var r2: u8[>..] = [];
    http::digest_credentials(r1, digest, "Mufasa", "Circle of Life", "GET", "/", "", 1, "");
    http::digest_credentials(r2, digest, "Mufasa", "Circle of Life", "GET", "/", "", 1, "");
    guard r1 != r2 else { print("auth: the cnonce was not random"); exit(1); }

    // Basic (RFC 7617's example) and Bearer.
    var b: u8[>..] = [];
    http::basic_credentials(b, "Aladdin", "open sesame");
    guard b == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" else { print("auth: Basic"); exit(1); }
    print("Authorization: ", b);
    var t: u8[>..] = [];
    http::bearer_credentials(t, "mF_9.B5f-4.1JqM");
    print("Authorization: ", t);

    // A challenge that cannot be answered: an algorithm not known.
    var no: u8[>..] = [];
    guard !http::digest_credentials(no, "realm=\"r\", nonce=\"n\", algorithm=SHA-1", "u", "p", "GET", "/", "", 1, "") else {
        print("auth: SHA-1 Digest was answered"); exit(1);
    }
    print("refused: Digest with SHA-1");
}

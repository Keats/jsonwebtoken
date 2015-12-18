#![feature(test)]
extern crate test;
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Algorithm, Header};

#[derive(Debug, PartialEq, Clone, RustcEncodable, RustcDecodable)]
struct Claims {
    sub: String,
    company: String
}

#[bench]
fn bench_encode(b: &mut test::Bencher) {
    let claim = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };

    b.iter(|| encode(&claim, "secret", Header::default()));
}

#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    b.iter(|| decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256));
}

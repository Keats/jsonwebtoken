#![feature(test)]
extern crate test;
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Algorithm};

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

    b.iter(|| encode(&claim, "secret", Algorithm::HS256));
}

#[bench]
fn bench_decode(b: &mut test::Bencher) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ".to_owned();
    b.iter(|| decode::<Claims>(
        token.clone(),
        "secret".to_owned(),
        Algorithm::HS256
    ));
}

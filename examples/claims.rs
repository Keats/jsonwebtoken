extern crate jwt;
extern crate rustc_serialize;

use rustc_serialize::{Encodable};
use jwt::{
    Algorithm,
    encode,
    decode
};

#[derive(Debug, RustcEncodable, RustcDecodable)]
struct Claims {
    sub: String,
    company: String
}

fn main() {
    let my_claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };
    let token = encode::<Claims>(my_claims, "secret".to_owned(), Algorithm::HS256).unwrap();
    let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
}

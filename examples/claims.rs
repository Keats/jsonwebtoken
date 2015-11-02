extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

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
    let key = "secret";
    let token = encode::<Claims>(my_claims, key.to_owned(), Algorithm::HS256).unwrap();
    let claims = decode::<Claims>(token.to_owned(), key.to_owned(), Algorithm::HS256).unwrap();
}

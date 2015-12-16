extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Algorithm};
use jwt::errors::{Error};

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
    let token = match encode(&my_claims, key, Algorithm::HS256) {
        Ok(t) => t,
        Err(_) => panic!() // in practice you would return the error
    };

    let claims = match decode::<Claims>(&token, key.as_ref(), Algorithm::HS256) {
        Ok(c) => c,
        Err(err) => match err {
            Error::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!()
        }
    };
}

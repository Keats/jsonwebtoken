extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Header, Algorithm};
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

    let mut header = Header::default();
    header.kid = Some("signing_key".to_owned());

    let token = match encode(&my_claims, key.as_ref(), header) {
        Ok(t) => t,
        Err(_) => panic!() // in practice you would return the error
    };

    let token_data = match decode::<Claims>(&token, key.as_ref(), Algorithm::HS256) {
        Ok(c) => c,
        Err(err) => match err {
            Error::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!()
        }
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}

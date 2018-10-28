extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;

use jwt::errors::ErrorKind;
use jwt::{decode, encode, Header, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = "secret";
    let token = match encode(&Header::default(), &my_claims, key.as_ref()) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let validation = Validation { sub: Some("b@b.com".to_string()), ..Validation::default() };
    let token_data = match decode::<Claims>(&token, key.as_ref(), &validation) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
            _ => panic!("Some other errors"),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}

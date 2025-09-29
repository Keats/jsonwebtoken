use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    company: String,
    exp: u64,
}

fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = b"secret";

    let mut extras = HashMap::with_capacity(1);
    extras.insert("custom".to_string(), "header".to_string());

    let header = Header {
        kid: Some("signing_key".to_owned()),
        alg: Algorithm::HS512,
        extras,
        ..Default::default()
    };

    let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);

    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!(),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
}

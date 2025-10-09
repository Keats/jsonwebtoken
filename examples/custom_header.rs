use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Validation, decode_with_custom_header, encode, header,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    company: String,
    exp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
struct CustomHeader {
    alg: Algorithm,
    custom: String,
    another_custom_field: Option<usize>,
}
impl header::FromEncoded for CustomHeader {}
impl header::Alg for CustomHeader {
    fn alg(&self) -> &Algorithm {
        &self.alg
    }
}

fn main() {
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = b"secret";

    let mut extras = HashMap::with_capacity(1);
    extras.insert("custom".to_string(), "header".to_string());

    let header = CustomHeader {
        alg: Algorithm::HS512,
        custom: "custom".into(),
        another_custom_field: 42.into(),
    };

    let token = match encode(&header, &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);

    let token_data = match decode_with_custom_header::<CustomHeader, Claims>(
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

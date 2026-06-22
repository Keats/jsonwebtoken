use serde::{Deserialize, Serialize};

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    aud: String,
    sub: String,
    company: String,
    exp: u64,
}

fn main() {
    let key = b"secret";
    let my_claims = Claims {
        aud: "me".to_owned(),
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: 10000000000,
    };
    let token = match encode(&Header::default(), &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    let validation = Validation::new()
        .with_algorithm(Algorithm::HS256)
        .with_subject("b@b.com".to_string())
        .with_audience(&["me"]);
    let token_data = match decode::<Claims>(&token, &DecodingKey::from_secret(key), &validation) {
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

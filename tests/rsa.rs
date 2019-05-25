extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;
extern crate chrono;

use chrono::Utc;
use jsonwebtoken::{decode, encode, sign, verify, Algorithm, Der, Header, Pkcs8, Validation};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
fn round_trip_sign_verification() {
    let privkey = include_bytes!("private_rsa_key.der");
    let encrypted = sign("hello world", Der::from(&&privkey[..]), Algorithm::RS256).unwrap();
    let is_valid =
        verify(&encrypted, "hello world", include_bytes!("public_rsa_key.der"), Algorithm::RS256)
            .unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let privkey = include_bytes!("private_rsa_key.der");
    let token =
        encode(&Header::new(Algorithm::RS256), &my_claims, Der::from(&&privkey[..])).unwrap();
    let token_data = decode::<Claims>(
        &token,
        include_bytes!("public_rsa_key.der"),
        &Validation::new(Algorithm::RS256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}

#[test]
#[should_panic(expected = "InvalidRsaKey")]
fn fails_with_different_key_format() {
    let privkey = include_bytes!("private_rsa_key.der");
    sign("hello world", Pkcs8::from(&&privkey[..]), Algorithm::RS256).unwrap();
}

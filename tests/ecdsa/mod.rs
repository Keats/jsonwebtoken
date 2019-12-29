use chrono::Utc;
use jsonwebtoken::{
    crypto::{sign, verify},
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
fn round_trip_sign_verification_pk8() {
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let pubkey = include_bytes!("public_ecdsa_key.pk8");

    let encrypted = sign("hello world", &EncodingKey::from_der(privkey), Algorithm::ES256).unwrap();
    let is_valid = verify(&encrypted, "hello world", &DecodingKey::from_der(pubkey), Algorithm::ES256).unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_sign_verification_pem() {
    let privkey_pem = include_bytes!("private_ecdsa_key.pem");
    let pubkey_pem = include_bytes!("public_ecdsa_key.pem");
    let encrypted =
        sign("hello world", &EncodingKey::from_ec_pem(privkey_pem).unwrap(), Algorithm::ES256)
            .unwrap();
    let is_valid = verify(
        &encrypted,
        "hello world",
        &DecodingKey::from_ec_pem(pubkey_pem).unwrap(),
        Algorithm::ES256,
    )
    .unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_claim() {
    let privkey_pem = include_bytes!("private_ecdsa_key.pem");
    let pubkey_pem = include_bytes!("public_ecdsa_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let token = encode(
        &Header::new(Algorithm::ES256),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey_pem).unwrap(),
    )
    .unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_ec_pem(pubkey_pem).unwrap(),
        &Validation::new(Algorithm::ES256),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[test]
fn roundtrip_with_jwtio_example() {
    // We currently do not support SEC1 so we use the converted PKCS8 formatted
    let privkey_pem = include_bytes!("private_jwtio_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_jwtio.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let token = encode(
        &Header::new(Algorithm::ES384),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey_pem).unwrap(),
    )
    .unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_ec_pem(pubkey_pem).unwrap(),
        &Validation::new(Algorithm::ES384),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
}

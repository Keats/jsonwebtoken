use chrono::Utc;
use jsonwebtoken::{
    crypto::{sign, verify},
    decode, encode, Algorithm, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

// TODO: remove completely?
//#[test]
//fn round_trip_sign_verification_pk8() {
//    let privkey = include_bytes!("private_ecdsa_key.pk8");
//    let encrypted = sign("hello world", privkey, Algorithm::ES256).unwrap();
//    let pubkey = include_bytes!("public_ecdsa_key.pk8");
//    let is_valid = verify(&encrypted, "hello world", pubkey, Algorithm::ES256).unwrap();
//    assert!(is_valid);
//}

#[test]
fn round_trip_sign_verification_pem() {
    let privkey = include_bytes!("private_ecdsa_key.pem");
    let pubkey = include_bytes!("public_ecdsa_key.pem");
    let encrypted =
        sign("hello world", &EncodingKey::from_ec_pem(privkey).unwrap(), Algorithm::ES256).unwrap();
    let is_valid = verify(&encrypted, "hello world", pubkey, Algorithm::ES256).unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_claim() {
    let privkey = include_bytes!("private_ecdsa_key.pem");
    let pubkey = include_bytes!("public_ecdsa_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let token = encode(
        &Header::new(Algorithm::ES256),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey).unwrap(),
    )
    .unwrap();
    let token_data = decode::<Claims>(&token, pubkey, &Validation::new(Algorithm::ES256)).unwrap();
    assert_eq!(my_claims, token_data.claims);
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[test]
fn roundtrip_with_jwtio_example() {
    // We currently do not support SEC1 so we use the converted PKCS8 formatted
    let privkey = include_bytes!("private_jwtio_pkcs8.pem");
    let pubkey = include_bytes!("public_jwtio.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let token = encode(
        &Header::new(Algorithm::ES384),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey).unwrap(),
    )
    .unwrap();
    let token_data = decode::<Claims>(&token, pubkey, &Validation::new(Algorithm::ES384)).unwrap();
    assert_eq!(my_claims, token_data.claims);
}

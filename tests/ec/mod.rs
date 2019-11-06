use chrono::Utc;
use jsonwebtoken::{decode, decode_pem, encode, sign, verify, Algorithm, Header, Key, Validation};
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
    let encrypted = sign("hello world", Key::Pkcs8(&privkey[..]), Algorithm::ES256).unwrap();
    let pubkey = include_bytes!("public_ecdsa_key.pk8");
    let is_valid = verify(&encrypted, "hello world", Key::Pkcs8(pubkey), Algorithm::ES256).unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_sign_verification_pem() {
    let privkey_pem = decode_pem(include_str!("private_ecdsa_key.pem")).unwrap();
    let privkey = privkey_pem.as_key().unwrap();
    let encrypted = sign("hello world", privkey, Algorithm::ES256).unwrap();
    let pubkey_pem = decode_pem(include_str!("public_ecdsa_key.pem")).unwrap();
    let pubkey = pubkey_pem.as_key().unwrap();
    let is_valid = verify(&encrypted, "hello world", pubkey, Algorithm::ES256).unwrap();
    assert!(is_valid);
}

#[test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let token =
        encode(&Header::new(Algorithm::ES256), &my_claims, Key::Pkcs8(&privkey[..])).unwrap();
    let pubkey = include_bytes!("public_ecdsa_key.pk8");
    let token_data =
        decode::<Claims>(&token, Key::Pkcs8(pubkey), &Validation::new(Algorithm::ES256)).unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}

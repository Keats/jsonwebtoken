extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;
extern crate chrono;

use chrono::Utc;
use jsonwebtoken::{decode, encode, sign, verify, Algorithm, Key, Header, Validation};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
fn round_trip_sign_verification() {
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let encrypted = sign("hello world", Key::Pkcs8(&privkey[..]), Algorithm::ES256).unwrap();
    let pubkey = include_bytes!("public_ecdsa_key.pk8");
    let is_valid = verify(&encrypted, "hello world", Key::Pkcs8(pubkey), Algorithm::ES256).unwrap();
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
    let token_data = decode::<Claims>(&token, Key::Pkcs8(pubkey), &Validation::new(Algorithm::ES256)).unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}

#[test]
#[should_panic(expected = "InvalidKeyFormat")]
fn fails_with_non_pkcs8_key_format() {
    let privkey = include_bytes!("private_rsa_key.der");
    let _encrypted = sign("hello world", Key::Der(&privkey[..]), Algorithm::ES256).unwrap();
}

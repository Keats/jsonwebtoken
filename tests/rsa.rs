extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;
extern crate chrono;

use chrono::Utc;
use jsonwebtoken::{decode, encode, sign, verify, Algorithm, Header, Key, Validation};

const RSA_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
fn round_trip_sign_verification() {
    let privkey = include_bytes!("private_rsa_key.der");
    for &alg in RSA_ALGORITHMS {
        let encrypted = sign("hello world", Key::Der(&privkey[..]), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", Key::Der(include_bytes!("public_rsa_key.der")), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let privkey = include_bytes!("private_rsa_key.der");

    for &alg in RSA_ALGORITHMS {
        let token = encode(&Header::new(alg), &my_claims, Key::Der(&privkey[..])).unwrap();
        let token_data = decode::<Claims>(
            &token,
            Key::Der(include_bytes!("public_rsa_key.der")),
            &Validation::new(alg),
        )
        .unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }
}

#[test]
#[should_panic(expected = "InvalidRsaKey")]
fn fails_with_different_key_format() {
    let privkey = include_bytes!("private_rsa_key.der");
    sign("hello world", Key::Pkcs8(&privkey[..]), Algorithm::RS256).unwrap();
}

#[test]
fn can_decode_jwt_io_example() {}

use chrono::Utc;
use jsonwebtoken::{decode, decode_pem, encode, sign, verify, Algorithm, Header, Key, Validation};
use serde_derive::{Deserialize, Serialize};

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
fn round_trip_sign_verification_der() {
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
fn round_trip_sign_verification_pem_pkcs1() {
    let privkey_pem = decode_pem(include_str!("private_rsa_key_pkcs1.pem")).unwrap();
    let pubkey_pem = decode_pem(include_str!("public_rsa_key_pkcs1.pem")).unwrap();

    for &alg in RSA_ALGORITHMS {
        let privkey_key = privkey_pem.as_key().unwrap();
        let pubkey_key = pubkey_pem.as_key().unwrap();
        let encrypted = sign("hello world", privkey_key, alg).unwrap();
        let is_valid = verify(&encrypted, "hello world", pubkey_key, alg).unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_sign_verification_pem_pkcs8() {
    let privkey_pem = decode_pem(include_str!("private_rsa_key_pkcs8.pem")).unwrap();
    let pubkey_pem = decode_pem(include_str!("public_rsa_key_pkcs8.pem")).unwrap();

    for &alg in RSA_ALGORITHMS {
        let privkey_key = privkey_pem.as_key().unwrap();
        let pubkey_key = pubkey_pem.as_key().unwrap();
        let encrypted = sign("hello world", privkey_key, alg).unwrap();
        let is_valid = verify(&encrypted, "hello world", pubkey_key, alg).unwrap();
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
fn rsa_modulus_exponent() {
    let modulus: Vec<u8> = vec![
        0xc9, 0x11, 0x3a, 0xac, 0x7b, 0x8d, 0x47, 0x44, 0x1b, 0x1c, 0xed, 0xc7, 0xdc, 0xab, 0x76,
        0xa4, 0xe2, 0x86, 0x56, 0x14, 0x2a, 0x19, 0x95, 0xc8, 0x9c, 0xe7, 0x6e, 0x40, 0xdc, 0x57,
        0xce, 0xe2, 0xa5, 0xbd, 0x04, 0xcb, 0x51, 0x3b, 0xf8, 0x97, 0x8b, 0x20, 0x82, 0x1e, 0x7f,
        0x09, 0x86, 0x22, 0xfd, 0xcb, 0xc8, 0xf9, 0x25, 0xd5, 0x4f, 0xd9, 0x0f, 0x59, 0x22, 0x97,
        0xc4, 0x95, 0xc1, 0x5d, 0xdf, 0xf8, 0x2e, 0x4b, 0xdc, 0x3e, 0xe5, 0x1a, 0x90, 0x1a, 0x00,
        0x91, 0xf8, 0x7e, 0x7a, 0x21, 0x55, 0x32, 0x1d, 0x95, 0xad, 0x4c, 0x96, 0xca, 0x3d, 0xcc,
        0x16, 0x5d, 0x07, 0x4d, 0x51, 0x7d, 0x2b, 0x04, 0x57, 0x2c, 0x07, 0x30, 0x91, 0x11, 0x22,
        0x4b, 0x79, 0xe9, 0x4e, 0x11, 0xd1, 0xc8, 0x8c, 0x6e, 0xcb, 0x46, 0x4c, 0x79, 0x97, 0xf1,
        0x54, 0xbe, 0x5a, 0xac, 0xc8, 0x70, 0xd5, 0x24, 0x44, 0x2c, 0x1f, 0x07, 0xa0, 0x67, 0xc6,
        0xfc, 0x0b, 0x47, 0xf3, 0xd0, 0x48, 0x13, 0xd8, 0xc3, 0x04, 0x76, 0x7d, 0x74, 0xb7, 0xa5,
        0x2b, 0xd6, 0xb5, 0xf3, 0x8c, 0xc0, 0x7f, 0xc2, 0xf0, 0xa0, 0xf2, 0xf1, 0xbc, 0x96, 0xf7,
        0x22, 0x5e, 0x67, 0x9d, 0xca, 0x8f, 0x71, 0x27, 0xca, 0x0c, 0x3a, 0x1d, 0x30, 0x50, 0x48,
        0x31, 0xce, 0x25, 0x43, 0x30, 0xca, 0x2f, 0x98, 0x2f, 0x9a, 0x25, 0xcb, 0x5c, 0x1d, 0x40,
        0x18, 0xb9, 0xbc, 0x28, 0x18, 0xdf, 0x13, 0xcb, 0x37, 0x2f, 0x9c, 0x6a, 0x8b, 0xec, 0x94,
        0xa1, 0xdf, 0xa3, 0xf0, 0xcb, 0x6f, 0x22, 0x3f, 0x35, 0xd9, 0xd9, 0x12, 0xe1, 0x03, 0x22,
        0x45, 0x53, 0x7f, 0x6f, 0x2d, 0xa1, 0xdd, 0x96, 0x3c, 0x2d, 0x85, 0x46, 0xae, 0xa6, 0x57,
        0x65, 0x37, 0x20, 0x9f, 0x6b, 0xa3, 0x9f, 0xcb, 0x8a, 0x8d, 0x72, 0xd9, 0x54, 0x3e, 0x53,
        0x75,
    ];
    let exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let privkey = include_bytes!("private_rsa_key.der");

    let encrypted = sign("hello world", Key::Der(&privkey[..]), Algorithm::RS256).unwrap();
    let is_valid = verify(
        &encrypted,
        "hello world",
        Key::ModulusExponent(&modulus, &exponent),
        Algorithm::RS256,
    )
    .unwrap();
    assert!(is_valid);
}

#[test]
#[should_panic(expected = "InvalidKeyFormat")]
fn fails_with_non_pkcs8_key_format() {
    let privkey = include_bytes!("private_rsa_key.der");
    let _encrypted = sign("hello world", Key::Der(&privkey[..]), Algorithm::ES256).unwrap();
}

use chrono::Utc;
use jsonwebtoken::{decode, decode_pem, encode_ec_public_pem, encode_ec_public_der, encode, sign, verify, Algorithm, Header, Key, Validation};
use serde::{Deserialize, Serialize};
use ring::{signature, signature::KeyPair};

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

#[test]
fn public_key_encoding() {
    let privkey_pem = decode_pem(include_str!("private_ecdsa_key.pem")).unwrap();
    let privkey = privkey_pem.as_key().unwrap();
    let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let ring_key = signature::EcdsaKeyPair::from_pkcs8(alg, match privkey {
        Key::Pkcs8(bytes) => bytes,
        _ => panic!("Unexpected")
    }).unwrap();

    let public_key_pem = encode_ec_public_pem(ring_key.public_key().as_ref()).unwrap();
    assert_eq!(include_str!("public_ecdsa_key.pem").trim(), public_key_pem.replace('\r', "").trim());

    let public_key_der = encode_ec_public_der(ring_key.public_key().as_ref()).unwrap();
    // The stored ".pk8" key is just the x coordinate of the EC key
    // It's not truly a pkcs8 formatted DER
    // To get around that, a prepended binary specifies the EC key, EC name,
    // and X coordinate length. The length is unlikely to change.. in the
    // event that it does, look at the pem file (convert base64 to hex) and find
    // where 0x03, 0x42 don't match up. 0x42 is the length.
    let mut stored_pk8_der = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
        0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00];
    stored_pk8_der.extend(include_bytes!("public_ecdsa_key.pk8").to_vec());
    assert_eq!(stored_pk8_der, public_key_der);
}
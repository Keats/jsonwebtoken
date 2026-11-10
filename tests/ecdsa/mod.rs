use serde::{Deserialize, Serialize};
#[cfg(feature = "use_pem")]
use time::OffsetDateTime;
use wasm_bindgen_test::wasm_bindgen_test;

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{sign, verify},
};
#[cfg(feature = "use_pem")]
use jsonwebtoken::{Header, Validation, decode, encode};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pk8() {
    let privkey = include_bytes!("private_ecdsa_key.pk8");
    let pubkey = include_bytes!("public_ecdsa_key.pk8");

    let encrypted =
        sign(b"hello world", &EncodingKey::from_ec_der(privkey), Algorithm::ES256).unwrap();
    let is_valid =
        verify(&encrypted, b"hello world", &DecodingKey::from_ec_der(pubkey), Algorithm::ES256)
            .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pem() {
    let privkey_pem = include_bytes!("private_ecdsa_key.pem");
    let pubkey_pem = include_bytes!("public_ecdsa_key.pem");
    let encrypted =
        sign(b"hello world", &EncodingKey::from_ec_pem(privkey_pem).unwrap(), Algorithm::ES256)
            .unwrap();
    let is_valid = verify(
        &encrypted,
        b"hello world",
        &DecodingKey::from_ec_pem(pubkey_pem).unwrap(),
        Algorithm::ES256,
    )
    .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_claim() {
    let privkey_pem = include_bytes!("private_ecdsa_key.pem");
    let pubkey_pem = include_bytes!("public_ecdsa_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
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

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ec_x_y() {
    let privkey = include_str!("private_ecdsa_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let x = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
    let y = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

    let encrypted = encode(
        &Header::new(Algorithm::ES256),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey.as_ref()).unwrap(),
    )
    .unwrap();
    let res = decode::<Claims>(
        &encrypted,
        &DecodingKey::from_ec_components(x, y).unwrap(),
        &Validation::new(Algorithm::ES256),
    );
    assert!(res.is_ok());
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ed_jwk() {
    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;

    let privkey = include_str!("private_ecdsa_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
        "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
        "kid": "ec01",
        "alg": "ES256",
        "use": "sig"
    }))
    .unwrap();

    let encrypted = encode(
        &Header::new(Algorithm::ES256),
        &my_claims,
        &EncodingKey::from_ec_pem(privkey.as_ref()).unwrap(),
    )
    .unwrap();
    let res = decode::<Claims>(
        &encrypted,
        &DecodingKey::from_jwk(&jwk).unwrap(),
        &Validation::new(Algorithm::ES256),
    );
    assert!(res.is_ok());
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn roundtrip_with_jwtio_example() {
    // We currently do not support SEC1 so we use the converted PKCS8 formatted
    let privkey_pem = include_bytes!("private_jwtio_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_jwtio.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
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

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ec_jwk_from_key() {
    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;

    let privkey = include_str!("private_ecdsa_key.pem");
    let encoding_key = EncodingKey::from_ec_pem(privkey.as_ref()).unwrap();
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256).unwrap();
    assert_eq!(
        jwk,
        serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
            "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
            "alg": "ES256",
        }))
        .unwrap()
    );
}

mod rfc7520 {
    use jsonwebtoken::{Algorithm, DecodingKey, crypto::verify};
    use wasm_bindgen_test::wasm_bindgen_test;

    // RFC 7520 section 3.2: EC P-521 key (x, y); section 4.3: ES512 JWS.
    const X: &str =
        "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
    const Y: &str =
        "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1";
    const SIGNING_INPUT: &str = concat!(
        "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
        ".",
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4g",
        "WW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwg",
        "dGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
    );
    const SIGNATURE: &str = concat!(
        "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv",
        "AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
    );

    #[test]
    #[wasm_bindgen_test]
    fn verify_rfc7520_es512_signature() {
        let key = DecodingKey::from_ec_components(X, Y).unwrap();
        assert!(verify(SIGNATURE, SIGNING_INPUT.as_bytes(), &key, Algorithm::ES512).unwrap());
    }

    #[test]
    #[wasm_bindgen_test]
    fn reject_modified_rfc7520_es512_input() {
        let key = DecodingKey::from_ec_components(X, Y).unwrap();
        let tampered = SIGNING_INPUT.replace("SXTi", "SXTj");
        assert!(!verify(SIGNATURE, tampered.as_bytes(), &key, Algorithm::ES512).unwrap());
    }

    #[cfg(feature = "use_pem")]
    mod pem {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
        use jsonwebtoken::{
            Algorithm, DecodingKey, EncodingKey,
            crypto::{sign, verify},
        };
        use wasm_bindgen_test::wasm_bindgen_test;

        use super::{SIGNING_INPUT, X, Y};

        // The private key `d` from the RFC, converted to PKCS#8.
        const PRIVATE_PK8_PEM: &[u8] = include_bytes!("private_rfc7520_p521.pem");

        #[test]
        #[wasm_bindgen_test]
        fn sign_with_rfc7520_key_and_verify() {
            // ECDSA signing may be randomized, so the RFC signature can't be reproduced;
            // check the round trip with the RFC key pair and the r || s length (66 bytes each).
            let enc = EncodingKey::from_ec_pem(PRIVATE_PK8_PEM).unwrap();
            let dec = DecodingKey::from_ec_components(X, Y).unwrap();
            let sig = sign(SIGNING_INPUT.as_bytes(), &enc, Algorithm::ES512).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(&sig).unwrap().len(), 132);
            assert!(verify(&sig, SIGNING_INPUT.as_bytes(), &dec, Algorithm::ES512).unwrap());
        }

        #[test]
        #[wasm_bindgen_test]
        fn jwk_from_rfc7520_private_key_matches_vector() {
            let enc = EncodingKey::from_ec_pem(PRIVATE_PK8_PEM).unwrap();
            let jwk = Jwk::from_encoding_key(&enc, Algorithm::ES512).unwrap();
            match jwk.algorithm {
                AlgorithmParameters::EllipticCurve(p) => {
                    assert_eq!(p.x, X);
                    assert_eq!(p.y, Y);
                }
                _ => panic!("expected EC key"),
            }
        }
    }
}

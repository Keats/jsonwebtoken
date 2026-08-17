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

macro_rules! ml_dsa_der_round_trip {
    ($name:ident, $alg:expr, $priv:literal, $pub_raw:literal) => {
        #[test]
        #[wasm_bindgen_test]
        fn $name() {
            let privkey = include_bytes!($priv);
            let pubkey = include_bytes!($pub_raw);

            let signed = sign(b"hello world", &EncodingKey::from_mldsa_der(privkey), $alg).unwrap();
            let is_valid =
                verify(&signed, b"hello world", &DecodingKey::from_mldsa_der(pubkey), $alg).unwrap();
            assert!(is_valid);

            // Wrong message must not verify.
            let is_valid =
                verify(&signed, b"goodbye world", &DecodingKey::from_mldsa_der(pubkey), $alg)
                    .unwrap();
            assert!(!is_valid);
        }
    };
}

ml_dsa_der_round_trip!(
    round_trip_der_44,
    Algorithm::MLDSA44,
    "private_ml_dsa_44.der",
    "public_ml_dsa_44.raw"
);
ml_dsa_der_round_trip!(
    round_trip_der_65,
    Algorithm::MLDSA65,
    "private_ml_dsa_65.der",
    "public_ml_dsa_65.raw"
);
ml_dsa_der_round_trip!(
    round_trip_der_87,
    Algorithm::MLDSA87,
    "private_ml_dsa_87.der",
    "public_ml_dsa_87.raw"
);

#[cfg(feature = "use_pem")]
macro_rules! ml_dsa_pem_round_trip_claim {
    ($name:ident, $alg:expr, $priv:literal, $pub:literal) => {
        #[cfg(feature = "use_pem")]
        #[test]
        #[wasm_bindgen_test]
        fn $name() {
            let privkey_pem = include_bytes!($priv);
            let pubkey_pem = include_bytes!($pub);
            let my_claims = Claims {
                sub: "b@b.com".to_string(),
                company: "ACME".to_string(),
                exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
            };
            let token = encode(
                &Header::new($alg),
                &my_claims,
                &EncodingKey::from_mldsa_pem(privkey_pem).unwrap(),
            )
            .unwrap();
            let token_data = decode::<Claims>(
                &token,
                &DecodingKey::from_mldsa_pem(pubkey_pem).unwrap(),
                &Validation::new($alg),
            )
            .unwrap();
            assert_eq!(my_claims, token_data.claims);
        }
    };
}

#[cfg(feature = "use_pem")]
ml_dsa_pem_round_trip_claim!(
    round_trip_pem_claim_44,
    Algorithm::MLDSA44,
    "private_ml_dsa_44.pem",
    "public_ml_dsa_44.pem"
);
#[cfg(feature = "use_pem")]
ml_dsa_pem_round_trip_claim!(
    round_trip_pem_claim_65,
    Algorithm::MLDSA65,
    "private_ml_dsa_65.pem",
    "public_ml_dsa_65.pem"
);
#[cfg(feature = "use_pem")]
ml_dsa_pem_round_trip_claim!(
    round_trip_pem_claim_87,
    Algorithm::MLDSA87,
    "private_ml_dsa_87.pem",
    "public_ml_dsa_87.pem"
);

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn ml_dsa_jwk_round_trip() {
    use jsonwebtoken::jwk::Jwk;

    let privkey_pem = include_bytes!("private_ml_dsa_65.pem");
    let encoding_key = EncodingKey::from_mldsa_pem(privkey_pem).unwrap();

    // EncodingKey -> AKP JWK -> DecodingKey, then verify a real token.
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::MLDSA65).unwrap();
    assert!(jwk.is_supported());

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 10000,
    };
    let token =
        encode(&Header::new(Algorithm::MLDSA65), &my_claims, &encoding_key).unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_jwk(&jwk).unwrap(),
        &Validation::new(Algorithm::MLDSA65),
    )
    .unwrap();
    assert_eq!(my_claims, token_data.claims);
}

// Helper: base64url (no pad) encode, matching the JWK `pub` encoding.
fn b64url(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
#[wasm_bindgen_test]
fn from_jwk_akp_valid_succeeds() {
    use jsonwebtoken::jwk::Jwk;

    let pub_raw = include_bytes!("public_ml_dsa_44.raw");
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": b64url(pub_raw),
    }))
    .unwrap();

    assert!(DecodingKey::from_jwk(&jwk).is_ok());
}

#[test]
#[wasm_bindgen_test]
fn from_jwk_akp_non_mldsa_alg_fails() {
    use jsonwebtoken::jwk::Jwk;

    let pub_raw = include_bytes!("public_ml_dsa_44.raw");
    // An AKP JWK declaring a non-ML-DSA algorithm must be rejected.
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "AKP",
        "alg": "SLH-DSA-SHA2-128s",
        "pub": b64url(pub_raw),
    }))
    .unwrap();

    assert!(!jwk.is_supported());
    assert!(DecodingKey::from_jwk(&jwk).is_err());
}

#[test]
#[wasm_bindgen_test]
fn from_jwk_akp_wrong_param_set_fails() {
    use jsonwebtoken::jwk::Jwk;

    // Declares ML-DSA-44 (expects a 1312-byte key) but carries an
    // ML-DSA-87 public key (2592 bytes).
    let pub_raw = include_bytes!("public_ml_dsa_87.raw");
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "AKP",
        "alg": "ML-DSA-44",
        "pub": b64url(pub_raw),
    }))
    .unwrap();

    assert!(DecodingKey::from_jwk(&jwk).is_err());
}

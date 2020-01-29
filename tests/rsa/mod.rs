use chrono::Utc;
use jsonwebtoken::{
    crypto::{sign, verify},
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

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
fn round_trip_sign_verification_pem_pkcs1() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    for &alg in RSA_ALGORITHMS {
        let encrypted =
            sign("hello world", &EncodingKey::from_rsa_pem(privkey_pem).unwrap(), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_sign_verification_pem_pkcs8() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");

    for &alg in RSA_ALGORITHMS {
        let encrypted =
            sign("hello world", &EncodingKey::from_rsa_pem(privkey_pem).unwrap(), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(), alg)
                .unwrap();
        assert!(is_valid);
    }
}

#[test]
fn round_trip_sign_verification_der() {
    let privkey_der = include_bytes!("private_rsa_key.der");
    let pubkey_der = include_bytes!("public_rsa_key.der");

    for &alg in RSA_ALGORITHMS {
        let encrypted = sign("hello world", &EncodingKey::from_rsa_der(privkey_der), alg).unwrap();
        let is_valid =
            verify(&encrypted, "hello world", &DecodingKey::from_rsa_der(pubkey_der), alg).unwrap();
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
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    for &alg in RSA_ALGORITHMS {
        let token =
            encode(&Header::new(alg), &my_claims, &EncodingKey::from_rsa_pem(privkey_pem).unwrap())
                .unwrap();
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(),
            &Validation::new(alg),
        )
        .unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }
}

#[test]
fn rsa_modulus_exponent() {
    let privkey = include_str!("private_rsa_key_pkcs1.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let n = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    let e = "AQAB";

    let encrypted = encode(
        &Header::new(Algorithm::RS256),
        &my_claims,
        &EncodingKey::from_rsa_pem(privkey.as_ref()).unwrap(),
    )
    .unwrap();
    let res = decode::<Claims>(
        &encrypted,
        &DecodingKey::from_rsa_components(n, e),
        &Validation::new(Algorithm::RS256),
    );
    assert!(res.is_ok());
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[test]
fn roundtrip_with_jwtio_example_jey() {
    let privkey_pem = include_bytes!("private_jwtio.pem");
    let pubkey_pem = include_bytes!("public_jwtio.pem");

    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };

    for &alg in RSA_ALGORITHMS {
        let token =
            encode(&Header::new(alg), &my_claims, &EncodingKey::from_rsa_pem(privkey_pem).unwrap())
                .unwrap();
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa_pem(pubkey_pem).unwrap(),
            &Validation::new(alg),
        )
        .unwrap();
        assert_eq!(my_claims, token_data.claims);
    }
}

use chrono::Utc;
use jsonwebtoken::{
    crypto::{sign, verify},
    dangerous_unsafe_decode, decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey,
    Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
fn sign_hs256() {
    let result =
        sign("hello world", &EncodingKey::from_secret(b"secret"), Algorithm::HS256).unwrap();
    let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    assert_eq!(result, expected);
}

#[test]
fn verify_hs256() {
    let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    let valid =
        verify(sig, "hello world", &DecodingKey::from_secret(b"secret"), Algorithm::HS256).unwrap();
    assert!(valid);
}

#[test]
fn encode_with_custom_header() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let mut header = Header::default();
    header.kid = Some("kid".to_string());
    let token = encode(&header, &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data =
        decode::<Claims>(&token, &DecodingKey::from_secret(b"secret"), &Validation::default())
            .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert_eq!("kid", token_data.header.kid.unwrap());
}

#[test]
fn round_trip_claim() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let token =
        encode(&Header::default(), &my_claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let token_data =
        decode::<Claims>(&token, &DecodingKey::from_secret(b"secret"), &Validation::default())
            .unwrap();
    assert_eq!(my_claims, token_data.claims);
    assert!(token_data.header.kid.is_none());
}

#[test]
fn decode_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
    let claims =
        decode::<Claims>(token, &DecodingKey::from_secret(b"secret"), &Validation::default());
    println!("{:?}", claims);
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidToken")]
fn decode_token_missing_parts() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let claims =
        decode::<Claims>(token, &DecodingKey::from_secret(b"secret"), &Validation::default());
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn decode_token_invalid_signature() {
    let token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
    let claims =
        decode::<Claims>(token, &DecodingKey::from_secret(b"secret"), &Validation::default());
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(b"secret"),
        &Validation::new(Algorithm::RS512),
    );
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidAlgorithm")]
fn encode_wrong_alg_family() {
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: Utc::now().timestamp() + 10000,
    };
    let claims = encode(&Header::default(), &my_claims, &EncodingKey::from_rsa_der(b"secret"));
    claims.unwrap();
}

#[test]
fn decode_token_with_bytes_secret() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.Hm0yvKH25TavFPz7J_coST9lZFYH1hQo0tvhvImmaks";
    let claims =
        decode::<Claims>(token, &DecodingKey::from_secret(b"\x01\x02\x03"), &Validation::default());
    assert!(claims.is_ok());
}

#[test]
fn decode_header_only() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.S";
    let header = decode_header(token).unwrap();
    assert_eq!(header.alg, Algorithm::HS256);
    assert_eq!(header.typ, Some("JWT".to_string()));
}

#[test]
fn dangerous_unsafe_decode_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
    let claims = dangerous_unsafe_decode::<Claims>(token);
    claims.unwrap();
}

#[test]
#[should_panic(expected = "InvalidToken")]
fn dangerous_unsafe_decode_token_missing_parts() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let claims = dangerous_unsafe_decode::<Claims>(token);
    claims.unwrap();
}

#[test]
fn dangerous_unsafe_decode_token_invalid_signature() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.wrong";
    let claims = dangerous_unsafe_decode::<Claims>(token);
    claims.unwrap();
}

#[test]
fn dangerous_unsafe_decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.fLxey-hxAKX5rNHHIx1_Ch0KmrbiuoakDVbsJjLWrx8fbjKjrPuWMYEJzTU3SBnYgnZokC-wqSdqckXUOunC-g";
    let claims = dangerous_unsafe_decode::<Claims>(token);
    claims.unwrap();
}

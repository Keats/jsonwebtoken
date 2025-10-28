use base64::{Engine, engine::general_purpose::STANDARD};
use wasm_bindgen_test::wasm_bindgen_test;

use jsonwebtoken::{
    Algorithm,
    header::{Alg, FromEncoded, Header},
};

static CERT_CHAIN: [&str; 3] = include!("cert_chain.json");

#[test]
#[wasm_bindgen_test]
fn x5c_der_empty_chain() {
    let header = Header { x5c: None, ..Default::default() };
    assert_eq!(header.x5c_der().unwrap(), None);

    let header = Header { x5c: Some(Vec::new()), ..Default::default() };
    assert_eq!(header.x5c_der().unwrap(), Some(Vec::new()));
}

#[test]
#[wasm_bindgen_test]
fn x5c_der_valid_chain() {
    let der_chain: Vec<Vec<u8>> =
        CERT_CHAIN.iter().map(|x| STANDARD.decode(x)).collect::<Result<_, _>>().unwrap();

    let x5c = Some(CERT_CHAIN.iter().map(ToString::to_string).collect());
    let header = Header { x5c, ..Default::default() };

    assert_eq!(header.x5c_der().unwrap(), Some(der_chain));
}

#[test]
#[wasm_bindgen_test]
fn x5c_der_invalid_chain() {
    let mut x5c: Vec<_> = CERT_CHAIN.iter().map(ToString::to_string).collect();
    x5c.push("invalid base64 data".to_string());

    let x5c = Some(x5c);
    let header = Header { x5c, ..Default::default() };

    assert!(header.x5c_der().is_err());
}

#[test]
#[wasm_bindgen_test]
fn decode_custom_header() {
    #[derive(Debug, PartialEq, Eq, Clone, serde::Deserialize)]
    struct CustomHeader {
        alg: Algorithm,
        typ: String,
        nonstandard_header: String,
    }
    impl Alg for CustomHeader {
        fn alg(&self) -> &Algorithm {
            &self.alg
        }
    }
    impl FromEncoded for CustomHeader {}

    let expected = CustomHeader {
        alg: Algorithm::HS256,
        typ: "JWT".into(),
        nonstandard_header: "traits are awesome".into(),
    };

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIm5vbnN0YW5kYXJkX2hlYWRlciI6InRyYWl0cyBhcmUgYXdlc29tZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzU5OTY4MTQ1fQ.c2VjcmV0";

    let header = jsonwebtoken::decode_custom_header::<CustomHeader>(token).unwrap();
    assert_eq!(header, expected);
}

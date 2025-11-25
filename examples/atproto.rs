use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use std::collections::HashMap;

// These were generated from Node.js using the @atproto/crypto library:
const TOKEN: &str = "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NksifQ.eyJzY29wZSI6ImNvbS5hdHByb3RvLmFjY2VzcyIsInN1YiI6ImRpZDpleGFtcGxlOmFsaWNlIiwiaWF0IjoxNzYyODA5ODk4LCJhdWQiOiJkaWQ6d2ViOmJza3kubmV0d29yayJ9.krVCmWVQ2lTdXzi7Gcu0vv-szONeYj7kSpevjGiGBJcJnY5NgweIhNEzsnqoi6ni9VONgIrYfCj6T7LhJr9isg";
const JWK: &str = r#"{ "kty": "EC", "x": "elgF6kwpkD00J9SPmoXBtaueneZf-77LnzrGrB7Ic7A", "y": "BTKRlhfwemkSQdB560lxw-Sg4GNH1gjkXXrryU-7jNM", "crv": "secp256k1" }"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwk: Jwk = serde_json::from_str(JWK).unwrap();
    let header = decode_header(TOKEN).unwrap();

    println!("Header Algorithm: {:#?}", header.alg);

    let validation = {
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&["did:web:bsky.network"]);
        validation.set_required_spec_claims(&["sub", "scope"]);
        validation.validate_exp = false;
        validation
    };

    let decoded_token = decode::<HashMap<String, serde_json::Value>>(
        TOKEN,
        &DecodingKey::from_jwk(&jwk).unwrap(),
        &validation,
    )?;

    println!("{:#?}", decoded_token);

    Ok(())
}

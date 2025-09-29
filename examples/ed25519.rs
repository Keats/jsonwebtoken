use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Validation, decode, encode, get_current_timestamp,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    sub: String,
    exp: u64,
}

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pkcs8 = signing_key.to_pkcs8_der().unwrap();
    let pkcs8 = pkcs8.as_bytes();
    // The `to_pkcs8_der` includes the public key, the first 48 bits are the private key.
    let pkcs8 = &pkcs8[..48];
    let encoding_key = EncodingKey::from_ed_der(pkcs8);

    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.as_bytes();
    let decoding_key = DecodingKey::from_ed_der(public_key);

    let claims = Claims { sub: "test".to_string(), exp: get_current_timestamp() };

    let token =
        encode(&jsonwebtoken::Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

    let validation = Validation::new(Algorithm::EdDSA);
    let _token_data = decode::<Claims>(&token, &decoding_key, &validation).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Jot {
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
    }

    impl Jot {
        fn new() -> Jot {
            let signing_key = SigningKey::generate(&mut OsRng);
            let pkcs8 = signing_key.to_pkcs8_der().unwrap();
            let pkcs8 = pkcs8.as_bytes();
            // The `to_pkcs8_der` includes the public key, the first 48 bits are the private key.
            let pkcs8 = &pkcs8[..48];
            let encoding_key = EncodingKey::from_ed_der(&pkcs8);

            let verifying_key = signing_key.verifying_key();
            let public_key = verifying_key.as_bytes();
            let decoding_key = DecodingKey::from_ed_der(public_key);

            Jot { encoding_key, decoding_key }
        }
    }

    #[test]
    fn test() {
        let jot = Jot::new();
        let claims = Claims { sub: "test".to_string(), exp: get_current_timestamp() };

        let token =
            encode(&jsonwebtoken::Header::new(Algorithm::EdDSA), &claims, &jot.encoding_key)
                .unwrap();

        let validation = Validation::new(Algorithm::EdDSA);
        let token_data = decode::<Claims>(&token, &jot.decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "test");
    }
}

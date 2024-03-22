use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use p256::SecretKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Validation,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: u64,
}

fn main() {
    let secret_key = SecretKey::random(&mut OsRng);
    let pkcs8 = secret_key.to_pkcs8_pem(Default::default()).unwrap();
    let pkcs8 = pkcs8.as_bytes();

    let encoding_key = EncodingKey::from_ed_der(pkcs8);

    let public_key_der = secret_key.public_key().to_public_key_der().unwrap();
    let decoding_key = DecodingKey::from_ed_der(public_key_der.as_bytes());

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
            let secret_key = SecretKey::random(&mut OsRng);
            let pkcs8 = secret_key.to_pkcs8_pem(Default::default()).unwrap();
            let pkcs8 = pkcs8.as_bytes();
            let encoding_key = EncodingKey::from_ed_der(pkcs8);

            let public_key_der = secret_key.public_key().to_public_key_der().unwrap();
            let decoding_key = DecodingKey::from_ed_der(public_key_der.as_bytes());

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

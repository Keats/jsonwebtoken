//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

mod algorithms;
mod crypto;
/// All the errors
pub mod errors;
mod header;
mod pem_decoder;
mod pem_encoder;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use crypto::{sign, verify};
pub use header::Header;
pub use serialization::TokenData;
pub use validation::Validation;

use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::{encode_part, from_jwt_part_claims};
use crate::validation::validate;

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key
///
/// ```rust,ignore
/// #[macro_use]
/// extern crate serde_derive;
/// use jsonwebtoken::{encode, Algorithm, Header};
///
/// /// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let token = encode(&Header::default(), &my_claims, "secret".as_ref()).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &[u8]) -> Result<String> {
    let encoded_header = encode_part(&header)?;
    let encoded_claims = encode_part(&claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*signing_input, key, header.alg)?;

    Ok([signing_input, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

/// Decode a token into a struct containing 2 fields: `claims` and `header`.
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust,ignore
/// #[macro_use]
/// extern crate serde_derive;
/// use jsonwebtoken::{decode, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_data = decode::<Claims>(&token, Key::Hmac("secret"), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &[u8],
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (signature, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(signing_input.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !verify(signature, signing_input, key, header.alg)? {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    if !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a token without any signature validation into a struct containing 2 fields: `claims` and `header`.
///
/// NOTE: Do not use this unless you know what you are doing! If the token's signature is invalid, it will *not* return an error.
///
/// ```rust,ignore
/// #[macro_use]
/// extern crate serde_derive;
/// use jsonwebtoken::{dangerous_unsafe_decode, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///     sub: String,
///     company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_data = dangerous_unsafe_decode::<Claims>(&token, &Validation::new(Algorithm::HS256));
/// ```
pub fn dangerous_unsafe_decode<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>> {
    let (_, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(signing_input.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    let (decoded_claims, _): (T, _) = from_jwt_part_claims(claims)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a token and return the Header. This is not doing any kind of validation: it is meant to be
/// used when you don't know which `alg` the token is using and want to find out.
///
/// If the token has an invalid format, it will return an error.
///
/// ```rust,ignore
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(signing_input.rsplitn(2, '.'));
    Header::from_encoded(header)
}

/// TODO
pub fn encode_rsa_public_pkcs1_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    pem_encoder::encode_rsa_public_pkcs1_pem(modulus, exponent)
}

/// TODO
pub fn encode_rsa_public_pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    pem_encoder::encode_rsa_public_pkcs1_der(modulus, exponent)
}

/// TODO
pub fn encode_rsa_public_pkcs8_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    pem_encoder::encode_rsa_public_pkcs8_pem(modulus, exponent)
}

/// TODO
pub fn encode_rsa_public_pkcs8_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    pem_encoder::encode_rsa_public_pkcs8_der(modulus, exponent)
}

/// TODO
pub fn encode_ec_public_pem(x_coordinate: &[u8]) -> Result<String> {
    pem_encoder::encode_ec_public_pem(x_coordinate)
}

/// TODO
pub fn encode_ec_public_der(x_coordinate: &[u8]) -> Result<Vec<u8>> {
    pem_encoder::encode_ec_public_der(x_coordinate)
}

//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

mod algorithms;
mod crypto;
mod decoding;
/// All the errors
pub mod errors;
mod header;
mod pem_decoder;
mod pem_encoder;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use crypto::{sign, verify};
pub use decoding::{dangerous_unsafe_decode, decode, decode_header, decode_rsa_jwk};
pub use header::Header;
pub use serialization::TokenData;
pub use validation::Validation;

use serde::ser::Serialize;

use crate::errors::Result;
use crate::serialization::encode_part;

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{encode, Algorithm, Header};
///
/// #[derive(Debug, Serialize, Deserialize)]
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
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*message, key, header.alg)?;

    Ok([message, signature].join("."))
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

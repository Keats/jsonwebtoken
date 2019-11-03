//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

mod algorithms;
mod crypto;
/// All the errors
pub mod errors;
mod header;
mod keys;
mod pem_decoder;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use crypto::{sign, verify};
pub use header::Header;
pub use keys::Key;
pub use pem_decoder::PemEncodedKey;
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
/// let token = encode(&Header::default(), &my_claims, Key::Hmac("secret".as_ref())).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: Key) -> Result<String> {
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
    key: Key,
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

/// Decode a PEM string to obtain its key
///
/// This must be a tagged PEM encoded key, tags start with `-----BEGIN ..-----`
/// and end with a `-----END ..-----`
///
/// ```rust
/// use jsonwebtoken::{decode_pem, sign, verify, Algorithm};
///
/// let pem_content = "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
/// kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
/// 950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
/// -----END PRIVATE KEY-----";
///
/// // First use decode_pem from jsonwebtoken
/// let privkey_pem = decode_pem(pem_content).unwrap();
/// // If it decodes Ok, then you can start using it with a given algorithm
/// let privkey = privkey_pem.as_key().unwrap();
///
/// // When using the as_key function, you do not need to wrap in Key::Der or Key::Pkcs8
/// // The same code can be used for public keys too.
/// let encrypted = sign("hello world", privkey, Algorithm::ES256).unwrap();
/// ```
pub fn decode_pem(content: &str) -> Result<PemEncodedKey> {
    PemEncodedKey::read(content)
}

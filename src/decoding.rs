use serde::de::DeserializeOwned;

use crate::crypto::{verify, verify_rsa_components};
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
use crate::serialization::from_jwt_part_claims;
use crate::validation::{validate, Validation};

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

/// Takes the result of a rsplit and ensure we only get 2 parts
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

/// Internal way to differentiate between public key types
enum DecodingKey<'a> {
    SecretOrPem(&'a [u8]),
    RsaModulusExponent { n: &'a str, e: &'a str },
}

fn _decode<T: DeserializeOwned>(
    token: &str,
    key: DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let is_valid = match key {
        DecodingKey::SecretOrPem(k) => verify(signature, message, k, header.alg),
        DecodingKey::RsaModulusExponent { n, e } => {
            verify_rsa_components(signature, message, (n, e), header.alg)
        }
    }?;

    if !is_valid {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode and validate a JWT using a secret for HS and a public PEM format for RSA/EC
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
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
/// let token_message = decode::<Claims>(&token, "secret".as_ref(), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &[u8],
    validation: &Validation,
) -> Result<TokenData<T>> {
    _decode(token, DecodingKey::SecretOrPem(key), validation)
}

/// Decode and validate a JWT using (n, e) base64 encoded public key components for RSA
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode_rsa_components, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let modulus = "some-base64-data";
/// let exponent = "some-base64-data";
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode_rsa_components::<Claims>(&token, &modulus, &exponent, &Validation::new(Algorithm::HS256));
/// ```
pub fn decode_rsa_components<T: DeserializeOwned>(
    token: &str,
    modulus: &str,
    exponent: &str,
    validation: &Validation,
) -> Result<TokenData<T>> {
    _decode(token, DecodingKey::RsaModulusExponent { n: modulus, e: exponent }, validation)
}

/// Decode a JWT without any signature verification/validations.
///
/// NOTE: Do not use this unless you know what you are doing! If the token's signature is invalid, it will *not* return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
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
/// let token_message = dangerous_unsafe_decode::<Claims>(&token);
/// ```
pub fn dangerous_unsafe_decode<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    let (decoded_claims, _): (T, _) = from_jwt_part_claims(claims)?;

    Ok(TokenData { header, claims: decoded_claims })
}

/// Decode a JWT without any signature verification/validations and return its [Header](struct.Header.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(message.rsplitn(2, '.'));
    Header::from_encoded(header)
}

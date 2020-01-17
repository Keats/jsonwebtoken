use std::borrow::Cow;

use serde::de::DeserializeOwned;

use crate::algorithms::AlgorithmFamily;
use crate::crypto::verify;
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
use crate::pem::decoder::PemEncodedKey;
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DecodingKeyKind<'a> {
    SecretOrDer(Cow<'a, [u8]>),
    RsaModulusExponent { n: &'a str, e: &'a str },
}

/// All the different kind of keys we can use to decode a JWT
/// This key can be re-used so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub struct DecodingKey<'a> {
    pub(crate) family: AlgorithmFamily,
    pub(crate) kind: DecodingKeyKind<'a>,
}

impl<'a> DecodingKey<'a> {
    /// If you're using HMAC, use this.
    pub fn from_secret(secret: &'a [u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Hmac,
            kind: DecodingKeyKind::SecretOrDer(Cow::Borrowed(secret)),
        }
    }

    /// If you're using HMAC with a base64 encoded, use this.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = base64::decode(&secret)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Hmac,
            kind: DecodingKeyKind::SecretOrDer(Cow::Owned(out)),
        })
    }

    /// If you are loading a public RSA key in a PEM format, use this.
    pub fn from_rsa_pem(key: &'a [u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(Cow::Owned(content.to_vec())),
        })
    }

    /// If you have (n, e) RSA public key components, use this.
    pub fn from_rsa_components(modulus: &'a str, exponent: &'a str) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::RsaModulusExponent { n: modulus, e: exponent },
        }
    }

    /// If you have a ECDSA public key in PEM format, use this.
    pub fn from_ec_pem(key: &'a [u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(Cow::Owned(content.to_vec())),
        })
    }

    /// If you know what you're doing and have a RSA DER encoded public key, use this.
    pub fn from_rsa_der(der: &'a [u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(Cow::Borrowed(der)),
        }
    }

    /// If you know what you're doing and have a RSA EC encoded public key, use this.
    pub fn from_ec_der(der: &'a [u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(Cow::Borrowed(der)),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.kind {
            DecodingKeyKind::SecretOrDer(b) => &b,
            DecodingKeyKind::RsaModulusExponent { .. } => unreachable!(),
        }
    }
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    for alg in &validation.algorithms {
        if key.family != alg.family() {
            return Err(new_error(ErrorKind::InvalidAlgorithm));
        }
    }

    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(message.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if !verify(signature, message, key, header.alg)? {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
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

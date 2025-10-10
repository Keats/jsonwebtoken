//! The cryptography of the `jsonwebtoken` crate is decoupled behind
//! [`JwtSigner`] and [`JwtVerifier`] traits. These make use of `RustCrypto`'s
//! [`Signer`] and [`Verifier`] traits respectively.
//!
//! [`JwtSigner`]: crate::crypto::JwtSigner
//! [`JwtVerifier`]: crate::crypto::JwtVerifier
//! [`Signer`]: signature::Signer
//! [`Verifier`]: signature::Verifier

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::{DecodingKey, EncodingKey};

#[cfg(feature = "aws_lc_rs")]
pub(crate) mod aws_lc;
#[cfg(feature = "botan")]
pub(crate) mod botan;
#[cfg(feature = "rust_crypto")]
pub(crate) mod rust_crypto;

use crate::serialization::{b64_decode, b64_encode};
use signature::{Signer, Verifier};

/// Trait providing the functionality to sign a JWT.
///
/// Allows an arbitrary crypto backend to be provided.
pub trait JwtSigner: Signer<Vec<u8>> {
    /// Return the [`Algorithm`] corresponding to the signing module.
    fn algorithm(&self) -> Algorithm;
}

/// Trait providing the functionality to verify a JWT.
///
/// Allows an arbitrary crypto backend to be provided.
pub trait JwtVerifier: Verifier<Vec<u8>> {
    /// Return the [`Algorithm`] corresponding to the signing module.
    fn algorithm(&self) -> Algorithm;
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    let provider = crate::encoding::jwt_signer_factory(&algorithm, key)?;
    Ok(b64_encode(provider.sign(message)))
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    let provider = crate::decoding::jwt_verifier_factory(&algorithm, key)?;
    Ok(provider.verify(message, &b64_decode(signature)?).is_ok())
}

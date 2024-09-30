use crate::algorithms::Algorithm;
use crate::decoding::{DecodingKey, DecodingKeyKind};
use crate::encoding::EncodingKey;
use crate::errors::Result;

pub(crate) mod ecdsa;
pub(crate) mod eddsa;
pub(crate) mod hmac;
pub(crate) mod rsa;

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
    match algorithm {
        Algorithm::ES256 | Algorithm::ES384 => ecdsa::sign(algorithm, key.inner(), message),
        Algorithm::EdDSA => eddsa::sign(key.inner(), message),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            hmac::sign_hmac(algorithm, key.inner(), message)
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => rsa::sign(algorithm, key.inner(), message),
    }
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
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            hmac::hmac_verify(algorithm, signature, key.as_bytes(), message)
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::verify(algorithm, signature, message, key.as_bytes())
        }
        Algorithm::EdDSA => eddsa::verify(signature, message, key.as_bytes()),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => match &key.kind {
            DecodingKeyKind::SecretOrDer(bytes) => {
                rsa::verify_der(algorithm, signature, message, bytes)
            }
            DecodingKeyKind::RsaModulusExponent { n, e } => {
                rsa::verify_from_components(algorithm, signature, message, (n, e))
            }
        },
    }
}

use ring::constant_time::verify_slices_are_equal;
use ring::{hmac, signature};

use crate::algorithms::Algorithm;
use crate::errors::{Result};
use crate::pem_decoder::PemEncodedKey;
use crate::serialization::{encode, decode};

pub(crate) mod rsa;
pub(crate) mod ecdsa;

/// The actual HS signing + encoding
pub(crate) fn sign_hmac(alg: hmac::Algorithm, key: &[u8], signing_input: &str) -> Result<String> {
    let digest = hmac::sign(&hmac::Key::new(alg, key), signing_input.as_bytes());
    Ok(encode(digest.as_ref()))
}


/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
/// `key` is the secret for HMAC and a pem encoded string otherwise
pub fn sign(signing_input: &str, key: &[u8], algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(hmac::HMAC_SHA256, key, signing_input),
        Algorithm::HS384 => sign_hmac(hmac::HMAC_SHA384, key, signing_input),
        Algorithm::HS512 => sign_hmac(hmac::HMAC_SHA512, key, signing_input),

        Algorithm::ES256 => {
            ecdsa::sign(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, key, signing_input)
        }
        Algorithm::ES384 => {
            ecdsa::sign(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, key, signing_input)
        }

        Algorithm::RS256 => rsa::sign(&signature::RSA_PKCS1_SHA256, key, signing_input),
        Algorithm::RS384 => rsa::sign(&signature::RSA_PKCS1_SHA384, key, signing_input),
        Algorithm::RS512 => rsa::sign(&signature::RSA_PKCS1_SHA512, key, signing_input),

        Algorithm::PS256 => rsa::sign(&signature::RSA_PSS_SHA256, key, signing_input),
        Algorithm::PS384 => rsa::sign(&signature::RSA_PSS_SHA384, key, signing_input),
        Algorithm::PS512 => rsa::sign(&signature::RSA_PSS_SHA512, key, signing_input),
    }
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA.
///
/// Only use this function if you want to do something other than JWT.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `signing_input` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    signing_input: &str,
    key: &[u8],
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the data with the key and compare if they are equal
            let signed = sign(signing_input, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 => {
            verify_ring_es(&signature::ECDSA_P256_SHA256_FIXED, signature, signing_input, key)
        }
        Algorithm::ES384 => {
            verify_ring_es(&signature::ECDSA_P384_SHA384_FIXED, signature, signing_input, key)
        }
        Algorithm::RS256 => {
            verify_ring_rsa(&signature::RSA_PKCS1_2048_8192_SHA256, signature, signing_input, key)
        }
        Algorithm::RS384 => {
            verify_ring_rsa(&signature::RSA_PKCS1_2048_8192_SHA384, signature, signing_input, key)
        }
        Algorithm::RS512 => {
            verify_ring_rsa(&signature::RSA_PKCS1_2048_8192_SHA512, signature, signing_input, key)
        }
        Algorithm::PS256 => {
            verify_ring_rsa(&signature::RSA_PSS_2048_8192_SHA256, signature, signing_input, key)
        }
        Algorithm::PS384 => {
            verify_ring_rsa(&signature::RSA_PSS_2048_8192_SHA384, signature, signing_input, key)
        }
        Algorithm::PS512 => {
            verify_ring_rsa(&signature::RSA_PSS_2048_8192_SHA512, signature, signing_input, key)
        }
    }
}

// TODO: see if we can remove stuff?

/// See Ring docs for more details
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = decode(signature)?;
    let public_key = signature::UnparsedPublicKey::new(alg, key);
    let res = public_key.verify(signing_input.as_bytes(), &signature_bytes);

    Ok(res.is_ok())
}

fn verify_ring_es(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let pem_key = PemEncodedKey::new(key)?;
    verify_ring(alg, signature, signing_input, pem_key.as_ec_public_key()?)
}

fn verify_ring_rsa(
    alg: &'static signature::RsaParameters,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let pem_key = PemEncodedKey::new(key)?;
    verify_ring(alg, signature, signing_input, pem_key.as_rsa_key()?)
}

use ring::constant_time::verify_slices_are_equal;
use ring::{hmac, signature};
use simple_asn1::BigUint;

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::pem_decoder::PemEncodedKey;
use crate::serialization::{decode, encode};

pub(crate) mod ecdsa;
pub(crate) mod rsa;

/// The actual HS signing + encoding
pub(crate) fn sign_hmac(alg: hmac::Algorithm, key: &[u8], message: &str) -> Result<String> {
    let digest = hmac::sign(&hmac::Key::new(alg, key), message.as_bytes());
    Ok(encode(digest.as_ref()))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
/// `key` is the secret for HMAC and a pem encoded string otherwise
pub fn sign(message: &str, key: &[u8], algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(hmac::HMAC_SHA256, key, message),
        Algorithm::HS384 => sign_hmac(hmac::HMAC_SHA384, key, message),
        Algorithm::HS512 => sign_hmac(hmac::HMAC_SHA512, key, message),

        Algorithm::ES256 => ecdsa::sign(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, key, message),
        Algorithm::ES384 => ecdsa::sign(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, key, message),

        Algorithm::RS256 => rsa::sign(&signature::RSA_PKCS1_SHA256, key, message),
        Algorithm::RS384 => rsa::sign(&signature::RSA_PKCS1_SHA384, key, message),
        Algorithm::RS512 => rsa::sign(&signature::RSA_PKCS1_SHA512, key, message),

        Algorithm::PS256 => rsa::sign(&signature::RSA_PSS_SHA256, key, message),
        Algorithm::PS384 => rsa::sign(&signature::RSA_PSS_SHA384, key, message),
        Algorithm::PS512 => rsa::sign(&signature::RSA_PSS_SHA512, key, message),
    }
}

fn rsa_alg_to_rsa_parameters(alg: Algorithm) -> &'static signature::RsaParameters {
    match alg {
        Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
        Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
        Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
        _ => unreachable!("Tried to get RSA signature for a non-rsa algorithm"),
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
/// For ECDSA/RSS, the `key` is the pem public key
pub fn verify(signature: &str, message: &str, key: &[u8], algorithm: Algorithm) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the message with the key and compare if they are equal
            let signed = sign(message, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 => {
            verify_ring_es(&signature::ECDSA_P256_SHA256_FIXED, signature, message, key)
        }
        Algorithm::ES384 => {
            verify_ring_es(&signature::ECDSA_P384_SHA384_FIXED, signature, message, key)
        }
        _ => verify_ring_rsa(rsa_alg_to_rsa_parameters(algorithm), signature, message, key),
    }
}

// TODO: see if we can remove stuff?

/// See Ring docs for more details
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    message: &str,
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = decode(signature)?;
    let public_key = signature::UnparsedPublicKey::new(alg, key);
    let res = public_key.verify(message.as_bytes(), &signature_bytes);

    Ok(res.is_ok())
}

fn verify_ring_es(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    message: &str,
    key: &[u8],
) -> Result<bool> {
    let pem_key = PemEncodedKey::new(key)?;
    verify_ring(alg, signature, message, pem_key.as_ec_public_key()?)
}

fn verify_ring_rsa(
    alg: &'static signature::RsaParameters,
    signature: &str,
    message: &str,
    key: &[u8],
) -> Result<bool> {
    let pem_key = PemEncodedKey::new(key)?;
    verify_ring(alg, signature, message, pem_key.as_rsa_key()?)
}

pub fn verify_rsa_modulus_exponent(
    alg: Algorithm,
    signature: &str,
    message: &str,
    components: (&str, &str),
) -> Result<bool> {
    let signature_bytes = decode(signature)?;
    let n = BigUint::from_bytes_be(&decode(components.0)?).to_bytes_be();
    let e = BigUint::from_bytes_be(&decode(components.1)?).to_bytes_be();
    let pubkey = signature::RsaPublicKeyComponents { n, e };
    let res = pubkey.verify(rsa_alg_to_rsa_parameters(alg), message.as_ref(), &signature_bytes);
    Ok(res.is_ok())
}

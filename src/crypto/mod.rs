use ring::constant_time::verify_slices_are_equal;
use ring::{hmac, signature};

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_decode, b64_encode};

pub(crate) mod ecdsa;
pub(crate) mod rsa;

/// The actual HS signing + encoding
/// Could be in its own file to match RSA/EC but it's 2 lines...
pub(crate) fn sign_hmac(alg: hmac::Algorithm, key: &[u8], message: &str) -> Result<String> {
    let digest = hmac::sign(&hmac::Key::new(alg, key), message.as_bytes());
    Ok(b64_encode(digest.as_ref()))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
///
/// `key` is the secret for HMAC and a pem encoded string otherwise
pub fn sign(message: &str, key: &[u8], algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(hmac::HMAC_SHA256, key, message),
        Algorithm::HS384 => sign_hmac(hmac::HMAC_SHA384, key, message),
        Algorithm::HS512 => sign_hmac(hmac::HMAC_SHA512, key, message),

        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::sign(ecdsa::alg_to_ec_signing(algorithm), key, message)
        }

        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => rsa::sign(rsa::alg_to_rsa_signing(algorithm), key, message),
    }
}

/// See Ring docs for more details
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    message: &str,
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    let public_key = signature::UnparsedPublicKey::new(alg, key);
    let res = public_key.verify(message.as_bytes(), &signature_bytes);

    Ok(res.is_ok())
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
/// For ECDSA/RSA, the `key` is the pem public key. If you want to verify using the public key
/// components (modulus/exponent), use `verify_rsa_components` instead.
pub fn verify(signature: &str, message: &str, key: &[u8], algorithm: Algorithm) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the message with the key and compare if they are equal
            let signed = sign(message, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let pem_key = PemEncodedKey::new(key)?;
            verify_ring(
                ecdsa::alg_to_ec_verification(algorithm),
                signature,
                message,
                pem_key.as_ec_public_key()?,
            )
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let pem_key = PemEncodedKey::new(key)?;
            verify_ring(
                rsa::alg_to_rsa_parameters(algorithm),
                signature,
                message,
                pem_key.as_rsa_key()?,
            )
        }
    }
}

/// Verify the signature given using the (n, e) components of a RSA public key.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify_rsa_components(
    signature: &str,
    message: &str,
    components: (&str, &str),
    alg: Algorithm,
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    rsa::verify_from_components(
        rsa::alg_to_rsa_parameters(alg),
        &signature_bytes,
        message,
        components,
    )
}

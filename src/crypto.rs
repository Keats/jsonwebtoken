use base64;
use ring::constant_time::verify_slices_are_equal;
use ring::{digest, hmac, rand, signature};
use untrusted;

use crate::algorithms::Algorithm;
use crate::errors::{new_error, ErrorKind, Result};
use crate::keys::Key;

/// The actual HS signing + encoding
fn sign_hmac(alg: &'static digest::Algorithm, key: Key, signing_input: &str) -> Result<String> {
    let signing_key = match key {
        Key::Hmac(bytes) => hmac::SigningKey::new(alg, bytes),
        _ => return Err(ErrorKind::InvalidKeyFormat)?,
    };
    let digest = hmac::sign(&signing_key, signing_input.as_bytes());

    Ok(base64::encode_config::<hmac::Signature>(&digest, base64::URL_SAFE_NO_PAD))
}

/// The actual ECDSA signing + encoding
fn sign_ecdsa(
    alg: &'static signature::EcdsaSigningAlgorithm,
    key: Key,
    signing_input: &str,
) -> Result<String> {
    let signing_key = match key {
        Key::Pkcs8(bytes) => {
            signature::EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(bytes))?
        }
        _ => {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
    };
    let rng = rand::SystemRandom::new();
    let sig = signing_key.sign(&rng, untrusted::Input::from(signing_input.as_bytes()))?;
    Ok(base64::encode_config(&sig, base64::URL_SAFE_NO_PAD))
}

/// The actual RSA signing + encoding
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
fn sign_rsa(
    alg: &'static dyn signature::RsaEncoding,
    key: Key,
    signing_input: &str,
) -> Result<String> {
    let key_pair = match key {
        Key::Der(bytes) => signature::RsaKeyPair::from_der(untrusted::Input::from(bytes))
            .map_err(|_| ErrorKind::InvalidRsaKey)?,
        Key::Pkcs8(bytes) => signature::RsaKeyPair::from_pkcs8(untrusted::Input::from(bytes))
            .map_err(|_| ErrorKind::InvalidRsaKey)?,
        _ => {
            return Err(ErrorKind::InvalidKeyFormat)?;
        }
    };

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    Ok(base64::encode_config::<[u8]>(&signature, base64::URL_SAFE_NO_PAD))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign(signing_input: &str, key: Key, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(&digest::SHA256, key, signing_input),
        Algorithm::HS384 => sign_hmac(&digest::SHA384, key, signing_input),
        Algorithm::HS512 => sign_hmac(&digest::SHA512, key, signing_input),

        Algorithm::ES256 => {
            sign_ecdsa(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, key, signing_input)
        }
        Algorithm::ES384 => {
            sign_ecdsa(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, key, signing_input)
        }

        Algorithm::RS256 => sign_rsa(&signature::RSA_PKCS1_SHA256, key, signing_input),
        Algorithm::RS384 => sign_rsa(&signature::RSA_PKCS1_SHA384, key, signing_input),
        Algorithm::RS512 => sign_rsa(&signature::RSA_PKCS1_SHA512, key, signing_input),

        Algorithm::PS256 => sign_rsa(&signature::RSA_PSS_SHA256, key, signing_input),
        Algorithm::PS384 => sign_rsa(&signature::RSA_PSS_SHA384, key, signing_input),
        Algorithm::PS512 => sign_rsa(&signature::RSA_PSS_SHA512, key, signing_input),
    }
}

/// See Ring docs for more details
fn verify_ring(
    alg: &dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
    let public_key_der = untrusted::Input::from(key);
    let message = untrusted::Input::from(signing_input.as_bytes());
    let expected_signature = untrusted::Input::from(signature_bytes.as_slice());

    let res = signature::verify(alg, public_key_der, message, expected_signature);

    Ok(res.is_ok())
}

fn verify_ring_es(
    alg: &dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: Key,
) -> Result<bool> {
    let bytes = match key {
        Key::Pkcs8(bytes) => bytes,
        _ => {
            return Err(ErrorKind::InvalidKeyFormat)?;
        }
    };
    verify_ring(alg, signature, signing_input, bytes)
}

fn verify_ring_rsa(
    alg: &dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: Key,
) -> Result<bool> {
    let bytes = match key {
        Key::Der(bytes) | Key::Pkcs8(bytes) => bytes,
        _ => {
            return Err(ErrorKind::InvalidKeyFormat)?;
        }
    };
    verify_ring(alg, signature, signing_input, bytes)
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
    key: Key,
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

use std::sync::Arc;

use base64;
use ring::{rand, digest, hmac, signature};
use ring::constant_time::verify_slices_are_equal;
use untrusted;

use errors::{Result, ErrorKind};


/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}


/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign(signing_input: &str, key: &[u8], algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let digest = match algorithm {
                Algorithm::HS256 => &digest::SHA256,
                Algorithm::HS384 => &digest::SHA384,
                Algorithm::HS512 => &digest::SHA512,
                _ => unreachable!(),
            };
            let key = hmac::SigningKey::new(digest, key);
            Ok(base64::encode_config(
                hmac::sign(&key, signing_input.as_bytes()).as_ref(),
                base64::URL_SAFE_NO_PAD
            ))
        },
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let ring_alg = match algorithm {
                Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
                Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
                Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
                _ => unreachable!(),
            };
            // Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
            let key_pair = Arc::new(
                signature::RSAKeyPair::from_der(
                    untrusted::Input::from(key)
                ).map_err(|_| ErrorKind::InvalidKey)?
            );
            let mut signing_state = signature::RSASigningState::new(key_pair)
                .map_err(|_| ErrorKind::InvalidKey)?;
            let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
            let rng = rand::SystemRandom::new();
            signing_state.sign(ring_alg, &rng, signing_input.as_bytes(), &mut signature)
                .map_err(|_| ErrorKind::InvalidKey)?;

            Ok(base64::encode_config(
                signature.as_ref(),
                base64::URL_SAFE_NO_PAD
            ))
        },
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
pub fn verify(signature: &str, signing_input: &str, key: &[u8], algorithm: Algorithm) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the data with the key and compare if they are equal
            let signed = sign(signing_input, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        },
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            // we use ring to verify using the public key given
            let verification_alg = match algorithm {
                Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                _ => unreachable!(),
            };
            let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
            let public_key_der = untrusted::Input::from(key);
            let message = untrusted::Input::from(signing_input.as_bytes());
            let expected_signature = untrusted::Input::from(signature_bytes.as_slice());

            let res = signature::verify(
                verification_alg,
                public_key_der,
                message,
                expected_signature,
            );

            Ok(res.is_ok())
        },
    }
}

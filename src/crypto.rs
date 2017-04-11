use std::sync::Arc;

use base64;
use ring::{rand, digest, hmac, signature};
use ring::constant_time::verify_slices_are_equal;
use serde::de::Deserialize;
use serde::ser::Serialize;
use untrusted;


use errors::{Result, ErrorKind};
use header::Header;
use serialization::{from_jwt_part, to_jwt_part, TokenData};


/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,

    RS256,
    RS384,
    RS512,
}


/// Take the payload of a JWT and sign it using the algorithm given.
/// Returns the base64 url safe encoded of the result
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

/// Encode the claims passed and sign the payload using the algorithm from the header and the key
pub fn encode<T: Serialize>(header: Header, claims: &T, key: &[u8]) -> Result<String> {
    let encoded_header = to_jwt_part(&header)?;
    let encoded_claims = to_jwt_part(&claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*signing_input, key.as_ref(), header.alg)?;

    Ok([signing_input, signature].join("."))
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key (`key`)
/// for RSA
///
/// `signature` is the signature part of a jwt (text after the second '.')
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
            println!("{:?}", res);

            Ok(res.is_ok())
        },
    }
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(ErrorKind::InvalidToken.into())
        }
    }}
}

/// Decode fn used internally by `decode` and `decode_without_verifying`
fn internal_decode<T: Deserialize>(token: &str, key: &[u8], algorithm: Algorithm, do_verification: bool) -> Result<TokenData<T>> {
    let (signature, signing_input) = expect_two!(token.rsplitn(2, '.'));

    if do_verification {
        if !verify(signature, signing_input, key, algorithm)? {
            return Err(ErrorKind::InvalidSignature.into());
        }
    }

    let (claims, header) = expect_two!(signing_input.rsplitn(2, '.'));

    let header: Header = from_jwt_part(header)?;
    if header.alg != algorithm {
        return Err(ErrorKind::WrongAlgorithmHeader.into());
    }
    let decoded_claims: T = from_jwt_part(claims)?;

    Ok(TokenData { header: header, claims: decoded_claims })
}

/// Decode a token into a struct containing Claims and Header
///
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Deserialize>(token: &str, key: &[u8], algorithm: Algorithm) -> Result<TokenData<T>> {
    internal_decode(token, key, algorithm, true)
}

/// Decode a token into a struct containing Claims and Header
/// WARNING: this will not do any verification so only use that at your own risk
///
/// If the token is invalid, it will return an error
pub fn decode_without_verification<T: Deserialize>(token: &str, key: &[u8], algorithm: Algorithm) -> Result<TokenData<T>> {
    internal_decode(token, key, algorithm, false)
}

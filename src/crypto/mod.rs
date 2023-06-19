#[cfg(not(target_arch = "wasm32"))]
use ring::constant_time::verify_slices_are_equal;
#[cfg(not(target_arch = "wasm32"))]
use ring::{hmac, signature};
#[cfg(target_arch = "wasm32")]
use sha2::{Sha256,Sha384,Sha512};
#[cfg(target_arch = "wasm32")]
use hmac::{Hmac, Mac};

use crate::algorithms::Algorithm;
use crate::decoding::{DecodingKey, DecodingKeyKind};
use crate::encoding::EncodingKey;
use crate::errors::Result;
use crate::serialization::{b64_decode, b64_encode};
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod ecdsa;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod eddsa;
pub(crate) mod rsa;

/// The actual HS signing + encoding
/// Could be in its own file to match RSA/EC but it's 2 lines...
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn sign_hmac(alg: hmac::Algorithm, key: &[u8], message: &[u8]) -> String {
    let digest = hmac::sign(&hmac::Key::new(alg, key), message);
    b64_encode(digest)
}
#[cfg(target_arch = "wasm32")]
type HmacSha256 = Hmac<Sha256>;
#[cfg(target_arch = "wasm32")]
type HmacSha384 = Hmac<Sha384>;
#[cfg(target_arch = "wasm32")]
type HmacSha512 = Hmac<Sha512>;
#[cfg(target_arch = "wasm32")]
pub(crate) fn sign_hmac(alg: Algorithm, key: &[u8], message: &[u8]) -> Result<String> {
    let  digest=  match alg {
        Algorithm::HS256 => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS384 => {
            let mut mac = HmacSha384::new_from_slice(key).map_err(|e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS512 => {
            let mut mac = HmacSha512::new_from_slice(key).map_err(|e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        _=>{
            return Err(crate::errors::new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }
    };
    Ok(b64_encode(&digest))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::HS256 => Ok(sign_hmac(hmac::HMAC_SHA256, key.inner(), message)),
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::HS384 => Ok(sign_hmac(hmac::HMAC_SHA384, key.inner(), message)),
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::HS512 => Ok(sign_hmac(hmac::HMAC_SHA512, key.inner(), message)),
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::sign(ecdsa::alg_to_ec_signing(algorithm), key.inner(), message)
        }
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::EdDSA => eddsa::sign(key.inner(), message),
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => rsa::sign(rsa::alg_to_rsa_signing(algorithm), key.inner(), message),
        #[cfg(target_arch = "wasm32")]
        Algorithm::HS256
        | Algorithm::HS384
        | Algorithm::HS512 => sign_hmac(algorithm, key.inner(), message),
        #[cfg(target_arch = "wasm32")]
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            rsa::sign(algorithm, key.inner(), message)
        },
        #[cfg(target_arch = "wasm32")]
        _ => Err(crate::errors::new_error(crate::errors::ErrorKind::InvalidAlgorithm)),
    }
}
#[cfg(not(target_arch = "wasm32"))]
/// See Ring docs for more details
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    let public_key = signature::UnparsedPublicKey::new(alg, key);
    let res = public_key.verify(message, &signature_bytes);

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
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the message with the key and compare if they are equal
            let signed = sign(message, &EncodingKey::from_secret(key.as_bytes()), algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::ES256 | Algorithm::ES384 => verify_ring(
            ecdsa::alg_to_ec_verification(algorithm),
            signature,
            message,
            key.as_bytes(),
        ),
        #[cfg(not(target_arch = "wasm32"))]
        Algorithm::EdDSA => verify_ring(
            eddsa::alg_to_ec_verification(algorithm),
            signature,
            message,
            key.as_bytes(),
        ),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            #[cfg(not(target_arch = "wasm32"))]
            let alg = rsa::alg_to_rsa_parameters(algorithm);
            match &key.kind {
                #[cfg(not(target_arch = "wasm32"))]
                DecodingKeyKind::SecretOrDer(bytes) => verify_ring(alg, signature, message, bytes),
                #[cfg(not(target_arch = "wasm32"))]
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    rsa::verify_from_components(alg, signature, message, (n, e))
                }
                #[cfg(target_arch = "wasm32")]
                DecodingKeyKind::SecretOrDer(bytes) => rsa::verify_der(algorithm, signature, message, bytes),
                #[cfg(target_arch = "wasm32")]
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    rsa::verify_from_components(algorithm, signature, message, (n, e))
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        _ => Err(crate::errors::new_error(crate::errors::ErrorKind::InvalidAlgorithm)),
    }
}

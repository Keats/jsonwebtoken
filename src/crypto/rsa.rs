#[cfg(not(target_arch = "wasm32"))]
use ring::{rand, signature};
#[cfg(target_arch = "wasm32")]
use rsa::{pss::Pss, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, traits::SignatureScheme, BigUint, pkcs1::DecodeRsaPrivateKey, pkcs1::DecodeRsaPublicKey};
#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::algorithms::Algorithm;
use crate::errors::{ErrorKind, Result, new_error};
use crate::serialization::{b64_decode, b64_encode};

/// Only used internally when validating RSA, to map from our enum to the Ring param structs.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn alg_to_rsa_parameters(alg: Algorithm) -> &'static signature::RsaParameters {
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

/// Only used internally when signing with RSA, to map from our enum to the Ring signing structs.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn alg_to_rsa_signing(alg: Algorithm) -> &'static dyn signature::RsaEncoding {
    match alg {
        Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
        Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
        Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
        Algorithm::PS256 => &signature::RSA_PSS_SHA256,
        Algorithm::PS384 => &signature::RSA_PSS_SHA384,
        Algorithm::PS512 => &signature::RSA_PSS_SHA512,
        _ => unreachable!("Tried to get RSA signature for a non-rsa algorithm"),
    }
}

/// The actual RSA signing + encoding
/// The key needs to be in PKCS8 format
/// Taken from Ring doc https://docs.rs/ring/latest/ring/signature/index.html
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn sign(
    alg: &'static dyn signature::RsaEncoding,
    key: &[u8],
    message: &[u8],
) -> Result<String> {
    let key_pair = signature::RsaKeyPair::from_der(key)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.description_().to_owned()))?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair.sign(alg, &rng, message, &mut signature).map_err(|_| ErrorKind::RsaFailedSigning)?;

    Ok(b64_encode(signature))
}

/// Checks that a signature is valid based on the (n, e) RSA pubkey components
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn verify_from_components(
    alg: &'static signature::RsaParameters,
    signature: &str,
    message: &[u8],
    components: (&[u8], &[u8]),
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    let pubkey = signature::RsaPublicKeyComponents { n: components.0, e: components.1 };
    let res = pubkey.verify(alg, message, &signature_bytes);
    Ok(res.is_ok())
}

#[cfg(target_arch = "wasm32")]
fn alg_to_pss(alg: Algorithm, digest_len: usize) -> Option<Pss> {
    match alg {
        Algorithm::PS256 => Some(Pss::new_with_salt::<Sha256>(digest_len)),
        Algorithm::PS384 => Some(Pss::new_with_salt::<Sha384>(digest_len)),
        Algorithm::PS512 => Some(Pss::new_with_salt::<Sha512>(digest_len)),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn alg_to_pkcs1_v15(alg: Algorithm) -> Option<Pkcs1v15Sign> {
    match alg {
        Algorithm::RS256 => Some(Pkcs1v15Sign::new::<Sha256>()),
        Algorithm::RS384 => Some(Pkcs1v15Sign::new::<Sha384>()),
        Algorithm::RS512 => Some(Pkcs1v15Sign::new::<Sha512>()),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn message_digest(alg: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
    match alg {
        Algorithm::RS256 | Algorithm::PS256 => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            let d = hasher.finalize();
            Ok(d.as_slice().to_vec())
        }
        Algorithm::RS384 | Algorithm::PS384 => {
            let mut hasher = Sha384::new();
            hasher.update(message);
            let d = hasher.finalize();
            Ok(d.as_slice().to_vec())
        }
        Algorithm::RS512 | Algorithm::PS512 => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            let d = hasher.finalize();
            Ok(d.as_slice().to_vec())
        }
        _ => Err(new_error(ErrorKind::InvalidAlgorithm)),
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn sign(alg: Algorithm,
                   key: &[u8],
                   message: &[u8]) -> Result<String> {
    let digest = message_digest(alg, message)?;
    let signatures_scheme_pkcs = alg_to_pkcs1_v15(alg);
    let signatures_scheme_pss = alg_to_pss(alg, digest.len());
    let private_key = RsaPrivateKey::from_pkcs1_der(key)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    let mut rng = rand::thread_rng();
    let signature = if let Some(signatures_scheme) = signatures_scheme_pkcs {
        signatures_scheme.sign(Some(&mut rng), &private_key, &digest)
            .map_err(|e| ErrorKind::RsaFailedSigning)?
    } else if let Some(signatures_scheme) = signatures_scheme_pss {
        signatures_scheme.sign(Some(&mut rng), &private_key, &digest)
            .map_err(|e| ErrorKind::RsaFailedSigning)?
    } else {
        return Err(new_error(ErrorKind::InvalidAlgorithmName));
    };
    Ok(b64_encode(&signature))
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn verify_from_components(
    alg: Algorithm,
    signature: &str,
    message: &[u8],
    components: (&[u8], &[u8]),
) -> Result<bool> {
    let n = BigUint::from_bytes_be(components.0);
    let e = BigUint::from_bytes_be(components.1);
    let pub_key = RsaPublicKey::new(n, e)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;

    verify(alg, signature, message, &pub_key)
}

#[cfg(target_arch = "wasm32")]
fn verify(alg: Algorithm, signature: &str, message: &[u8], pub_key: &RsaPublicKey) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    let digest = message_digest(alg, message)?;
    let signatures_scheme_pkcs = alg_to_pkcs1_v15(alg);
    let signatures_scheme_pss = alg_to_pss(alg, digest.len());
    if let Some(signatures_scheme) = signatures_scheme_pkcs {
        signatures_scheme.verify(&pub_key, &digest, &signature_bytes)
            .map_err(|e| ErrorKind::InvalidSignature)?;
    } else if let Some(signatures_scheme) = signatures_scheme_pss {
        signatures_scheme
            .verify(&pub_key, &digest, &signature_bytes)
            .map_err(|e| ErrorKind::InvalidSignature)?;
    } else {
        return Err(new_error(ErrorKind::InvalidAlgorithmName));
    };
    Ok(true)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn verify_der(
    alg: Algorithm,
    signature: &str,
    message: &[u8],
    bytes: &[u8],
) -> Result<bool> {
    let pub_key = RsaPublicKey::from_pkcs1_der(bytes).map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    verify(alg, signature, message, &pub_key)
}

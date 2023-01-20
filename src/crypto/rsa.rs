use ring::{rand, signature};

use crate::algorithms::Algorithm;
use crate::errors::{ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};

/// Only used internally when validating RSA, to map from our enum to the Ring param structs.
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
pub(crate) fn sign(
    alg: &'static dyn signature::RsaEncoding,
    key: &[u8],
    message: &[u8],
) -> Result<String> {
    let key_pair = signature::RsaKeyPair::from_der(key)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.description_()))?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair.sign(alg, &rng, message, &mut signature).map_err(|_| ErrorKind::RsaFailedSigning)?;

    Ok(b64_encode(signature))
}

/// Checks that a signature is valid based on the (n, e) RSA pubkey components
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

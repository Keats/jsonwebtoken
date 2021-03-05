use ring::{rand, signature};

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::serialization::b64_encode;

/// Only used internally when validating EC, to map from our enum to the Ring EcdsaVerificationAlgorithm structs.
pub(crate) fn alg_to_ec_verification(
    alg: Algorithm,
) -> &'static signature::EcdsaVerificationAlgorithm {
    match alg {
        Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
        Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

/// Only used internally when signing EC, to map from our enum to the Ring EcdsaVerificationAlgorithm structs.
pub(crate) fn alg_to_ec_signing(alg: Algorithm) -> &'static signature::EcdsaSigningAlgorithm {
    match alg {
        Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

/// The actual ECDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(
    alg: &'static signature::EcdsaSigningAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<String> {
    let signing_key = signature::EcdsaKeyPair::from_pkcs8(alg, key)?;
    let rng = rand::SystemRandom::new();
    let out = signing_key.sign(&rng, message)?;
    Ok(b64_encode(out))
}

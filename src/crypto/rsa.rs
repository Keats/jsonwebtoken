use ring::{rand, signature};
use simple_asn1::BigUint;

use crate::algorithms::Algorithm;
use crate::errors::{ErrorKind, Result};
use crate::pem::decoder::PemEncodedKey;
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
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
pub(crate) fn sign(
    alg: &'static dyn signature::RsaEncoding,
    key: &[u8],
    message: &str,
) -> Result<String> {
    let pem_key = PemEncodedKey::new(key)?;
    let key_pair = signature::RsaKeyPair::from_der(pem_key.as_rsa_key()?)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, message.as_bytes(), &mut signature)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    Ok(b64_encode(&signature))
}

pub(crate) fn verify_from_components(
    alg: &'static signature::RsaParameters,
    signature_bytes: &[u8],
    message: &str,
    components: (&str, &str),
) -> Result<bool> {
    let n = BigUint::from_bytes_be(&b64_decode(components.0)?).to_bytes_be();
    let e = BigUint::from_bytes_be(&b64_decode(components.1)?).to_bytes_be();
    let pubkey = signature::RsaPublicKeyComponents { n, e };
    let res = pubkey.verify(alg, message.as_ref(), &signature_bytes);
    Ok(res.is_ok())
}

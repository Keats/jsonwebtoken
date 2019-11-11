use ring::{rand, signature};
use simple_asn1::BigUint;

use crate::errors::{ErrorKind, Result};
use crate::pem_decoder::PemEncodedKey;
use crate::serialization::{b64_encode, b64_decode};
use crate::algorithms::Algorithm;


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
    signature_bytes: &[u8],
    message: &str,
    components: (&str, &str),
    alg: Algorithm) -> Result<bool> {
    let n = BigUint::from_bytes_be(&b64_decode(components.0)?).to_bytes_be();
    let e = BigUint::from_bytes_be(&b64_decode(components.1)?).to_bytes_be();
    let pubkey = signature::RsaPublicKeyComponents { n, e };
    let res = pubkey.verify(alg_to_rsa_parameters(alg), message.as_ref(), &signature_bytes);
    Ok(res.is_ok())
}

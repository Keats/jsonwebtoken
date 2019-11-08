use ring::{rand, signature};

use crate::errors::{Result};
use crate::pem_decoder::PemEncodedKey;
use crate::serialization::encode;

/// The actual ECDSA signing + encoding
pub fn sign(
    alg: &'static signature::EcdsaSigningAlgorithm,
    key: &[u8],
    signing_input: &str,
) -> Result<String> {
    let pem_key = PemEncodedKey::new(key)?;
    let signing_key = signature::EcdsaKeyPair::from_pkcs8(alg, pem_key.as_ec_private_key()?)?;
    let rng = rand::SystemRandom::new();
    let out = signing_key.sign(&rng, signing_input.as_bytes())?;
    Ok(encode(out.as_ref()))
}

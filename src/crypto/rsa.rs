use ring::{rand, signature};

use crate::errors::{ErrorKind, Result};
use crate::pem_decoder::PemEncodedKey;
use crate::serialization::encode;

/// The actual RSA signing + encoding
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
pub fn sign(
    alg: &'static dyn signature::RsaEncoding,
    key: &[u8],
    signing_input: &str,
) -> Result<String> {
    let pem_key = PemEncodedKey::new(key)?;
    let key_pair = signature::RsaKeyPair::from_der(pem_key.as_rsa_key()?)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    Ok(encode(&signature))
}

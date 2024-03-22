use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};

fn parse_key(key: &[u8]) -> Result<SigningKey> {
    let key = key.try_into().map_err(|_| new_error(ErrorKind::InvalidEddsaKey))?;
    let signing_key = SigningKey::from_bytes(key);
    Ok(signing_key)
}

pub(crate) fn verify(signature: &str, message: &[u8], key: &[u8]) -> Result<bool> {
    let signature = b64_decode(signature)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_e| new_error(ErrorKind::InvalidSignature))?;
    let key = key.try_into().map_err(|_| new_error(ErrorKind::InvalidEddsaKey))?;
    let verifying_key =
        VerifyingKey::from_bytes(key).map_err(|_| new_error(ErrorKind::InvalidEddsaKey))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let key = key[16..].into();
    let signing_key = parse_key(key)?;
    let out = signing_key.sign(message);
    Ok(b64_encode(out.to_bytes()))
}

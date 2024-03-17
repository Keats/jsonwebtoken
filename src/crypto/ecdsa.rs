use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::serialization::{b64_decode, b64_encode};

/// The actual ECDSA signing + encoding
/// The key needs to be in PKCS8 format
pub(crate) fn sign(alg: Algorithm, key: &[u8], message: &[u8]) -> Result<String> {
    match alg {
        Algorithm::ES256 => es256_sign(key, message),
        Algorithm::ES384 => es384_sign(key, message),

        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

fn es256_sign(key: &[u8], message: &[u8]) -> Result<String> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use p256::SecretKey;
    let secret_key = SecretKey::from_pkcs8_der(key)
        .map_err(|_e| crate::errors::ErrorKind::InvalidEcdsaKey)?;
    let signing_key: SigningKey = secret_key.into();

    let signature: Signature = signing_key.sign(message);
    let bytes = signature.to_bytes();
    Ok(b64_encode(bytes))
}

fn es384_sign(key: &[u8], message: &[u8]) -> Result<String> {
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use p384::SecretKey;
    let secret_key = SecretKey::from_pkcs8_der(key)
        .map_err(|_e| crate::errors::ErrorKind::InvalidEcdsaKey)?;
    let signing_key: SigningKey = secret_key.into();
    let signature: Signature = signing_key.sign(message);
    let bytes = signature.to_bytes();
    Ok(b64_encode(bytes))
}

pub(crate) fn verify(alg: Algorithm, signature: &str, message: &[u8], key: &[u8]) -> Result<bool> {
    match alg {
        Algorithm::ES256 => es256_verify(signature, message, key),
        Algorithm::ES384 => es384_verify(signature, message, key),
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

fn es384_verify(signature: &str, message: &[u8], key: &[u8]) -> Result<bool> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::PublicKey;

    let public_key = PublicKey::from_sec1_bytes(key)
        .map_err(|_e| crate::errors::ErrorKind::InvalidEcdsaKey)?;
    let verifying_key: VerifyingKey = public_key.into();
    let signature = Signature::from_slice(&b64_decode(signature)?)
        .map_err(|_e| crate::errors::ErrorKind::InvalidSignature)?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

fn es256_verify(signature: &str, message: &[u8], key: &[u8]) -> Result<bool> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::PublicKey;
    let public_key =
        PublicKey::from_sec1_bytes(key).map_err(|_e| crate::errors::ErrorKind::InvalidEcdsaKey)?;
    let verifying_key: VerifyingKey = public_key.into();
    let signature = Signature::from_slice(&b64_decode(signature)?)
        .map_err(|_e| crate::errors::ErrorKind::InvalidSignature)?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}
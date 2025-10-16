use ::rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts};
use p256::{ecdsa::SigningKey as P256SigningKey, pkcs8::DecodePrivateKey};
use p384::ecdsa::SigningKey as P384SigningKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier},
    errors::{self, Error, ErrorKind},
    jwk::{EllipticCurve, ThumbprintHash},
};

mod ecdsa;
mod eddsa;
mod hmac;
mod rsa;

/// Given a DER encoded private key, extract the RSA public key components (n, e)
pub fn extract_rsa_public_key_components(key_content: &[u8]) -> errors::Result<(Vec<u8>, Vec<u8>)> {
    let private_key = RsaPrivateKey::from_pkcs1_der(key_content)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    let public_key = private_key.to_public_key();
    Ok((public_key.n().to_bytes_be(), public_key.e().to_bytes_be()))
}

/// Given a DER encoded private key and an algorithm, extract the associated curve
/// and the EC public key components (x, y)
pub fn extract_ec_public_key_coordinates(
    key_content: &[u8],
    alg: Algorithm,
) -> errors::Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    match alg {
        Algorithm::ES256 => {
            let signing_key = P256SigningKey::from_pkcs8_der(key_content)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
            let public_key = signing_key.verifying_key();
            let encoded = public_key.to_encoded_point(false);
            match encoded.coordinates() {
                p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                    Ok((EllipticCurve::P256, x.to_vec(), y.to_vec()))
                }
                _ => Err(ErrorKind::InvalidEcdsaKey.into()),
            }
        }
        Algorithm::ES384 => {
            let signing_key = P384SigningKey::from_pkcs8_der(key_content)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
            let public_key = signing_key.verifying_key();
            let encoded = public_key.to_encoded_point(false);
            match encoded.coordinates() {
                p384::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                    Ok((EllipticCurve::P384, x.to_vec(), y.to_vec()))
                }
                _ => Err(ErrorKind::InvalidEcdsaKey.into()),
            }
        }
        _ => Err(ErrorKind::InvalidEcdsaKey.into()),
    }
}

/// Given some data and a name of a hash function, compute hash_function(data)
pub fn compute_digest(data: &[u8], hash_function: ThumbprintHash) -> Vec<u8> {
    match hash_function {
        ThumbprintHash::SHA256 => Sha256::digest(data).to_vec(),
        ThumbprintHash::SHA384 => Sha384::digest(data).to_vec(),
        ThumbprintHash::SHA512 => Sha512::digest(data).to_vec(),
    }
}

define_default_provider!("rust_crypto", "https://github.com/RustCrypto");

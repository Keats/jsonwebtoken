use aws_lc_rs::{
    digest,
    signature::{self as aws_sig, KeyPair},
};

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
    let key_pair = aws_sig::RsaKeyPair::from_der(key_content)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    let public = key_pair.public_key();
    let components = aws_sig::RsaPublicKeyComponents::<Vec<u8>>::from(public);
    Ok((components.n, components.e))
}

/// Given a DER encoded private key and an algorithm, extract the associated curve
/// and the EC public key components (x, y)
pub fn extract_ec_public_key_coordinates(
    key_content: &[u8],
    alg: Algorithm,
) -> errors::Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
    };

    let (signing_alg, curve, pub_elem_bytes) = match alg {
        Algorithm::ES256 => (&ECDSA_P256_SHA256_FIXED_SIGNING, EllipticCurve::P256, 32),
        Algorithm::ES384 => (&ECDSA_P384_SHA384_FIXED_SIGNING, EllipticCurve::P384, 48),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };

    let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_content)
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;

    let pub_bytes = key_pair.public_key().as_ref();
    if pub_bytes[0] != 4 {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }

    let (x, y) = pub_bytes[1..].split_at(pub_elem_bytes);
    Ok((curve, x.to_vec(), y.to_vec()))
}

/// Given some data and a name of a hash function, compute hash_function(data)
pub fn compute_digest(data: &[u8], hash_function: ThumbprintHash) -> Vec<u8> {
    let algorithm = match hash_function {
        ThumbprintHash::SHA256 => &digest::SHA256,
        ThumbprintHash::SHA384 => &digest::SHA384,
        ThumbprintHash::SHA512 => &digest::SHA512,
    };
    digest::digest(algorithm, data).as_ref().to_vec()
}

define_default_provider!("aws_lc_rs", "https://github.com/aws/aws-lc-rs");

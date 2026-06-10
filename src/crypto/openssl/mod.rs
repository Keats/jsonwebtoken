//! `openssl` based [`CryptoProvider`].

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

use crate::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
    errors::{self, Error, ErrorKind},
    jwk::{EllipticCurve, ThumbprintHash},
};

mod ecdsa;
mod eddsa;
mod hmac;
mod rsa;

fn rsa_components_from_private_key(key_content: &[u8]) -> errors::Result<(Vec<u8>, Vec<u8>)> {
    let rsa_key = Rsa::private_key_from_der(key_content)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    let n = rsa_key.n().to_vec();
    let e = rsa_key.e().to_vec();
    Ok((n, e))
}

fn rsa_components_from_public_key(key_content: &[u8]) -> errors::Result<(Vec<u8>, Vec<u8>)> {
    let rsa_key = Rsa::public_key_from_der_pkcs1(key_content)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
    let n = rsa_key.n().to_vec();
    let e = rsa_key.e().to_vec();
    Ok((n, e))
}

fn ec_components_from_private_key(
    key_content: &[u8],
    alg: Algorithm,
) -> errors::Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let (curve, nid, field_size) = match alg {
        Algorithm::ES256 => (EllipticCurve::P256, Nid::X9_62_PRIME256V1, 32),
        Algorithm::ES384 => (EllipticCurve::P384, Nid::SECP384R1, 48),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };

    let pkey = PKey::private_key_from_der(key_content)
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let ec_key = pkey.ec_key().map_err(|_| ErrorKind::InvalidEcdsaKey)?;

    let group = EcGroup::from_curve_name(nid).map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let mut ctx = BigNumContext::new().map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let pub_bytes = ec_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;

    if pub_bytes[0] != 4 || pub_bytes.len() != 1 + field_size * 2 {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }

    let (x, y) = pub_bytes[1..].split_at(field_size);
    Ok((curve, x.to_vec(), y.to_vec()))
}

fn compute_digest(data: &[u8], hash_function: ThumbprintHash) -> errors::Result<Vec<u8>> {
    let digest_type = match hash_function {
        ThumbprintHash::SHA256 => MessageDigest::sha256(),
        ThumbprintHash::SHA384 => MessageDigest::sha384(),
        ThumbprintHash::SHA512 => MessageDigest::sha512(),
    };
    Ok(openssl::hash::hash(digest_type, data)
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_vec())
}

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    let jwt_signer = match algorithm {
        Algorithm::HS256 => Box::new(hmac::Hs256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::HS384 => Box::new(hmac::Hs384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::HS512 => Box::new(hmac::Hs512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::ES256 => Box::new(ecdsa::Es256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::ES384 => Box::new(ecdsa::Es384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS256 => Box::new(rsa::Rsa256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS384 => Box::new(rsa::Rsa384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS512 => Box::new(rsa::Rsa512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS256 => Box::new(rsa::RsaPss256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS384 => Box::new(rsa::RsaPss384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS512 => Box::new(rsa::RsaPss512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::EdDSA => Box::new(eddsa::EdDSASigner::new(key)?) as Box<dyn JwtSigner>,
    };

    Ok(jwt_signer)
}

fn new_verifier(
    algorithm: &Algorithm,
    key: &DecodingKey,
) -> Result<Box<dyn super::JwtVerifier>, Error> {
    let jwt_verifier = match algorithm {
        Algorithm::HS256 => Box::new(hmac::Hs256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS384 => Box::new(hmac::Hs384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS512 => Box::new(hmac::Hs512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES256 => Box::new(ecdsa::Es256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES384 => Box::new(ecdsa::Es384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS256 => Box::new(rsa::Rsa256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS384 => Box::new(rsa::Rsa384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS512 => Box::new(rsa::Rsa512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS256 => Box::new(rsa::RsaPss256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS384 => Box::new(rsa::RsaPss384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS512 => Box::new(rsa::RsaPss512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::EdDSA => Box::new(eddsa::EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
    };

    Ok(jwt_verifier)
}

/// The default [`CryptoProvider`] backed by [`openssl`](https://github.com/sfackler/rust-openssl).
pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: rsa_components_from_private_key,
        rsa_pub_components_from_public_key: rsa_components_from_public_key,
        ec_pub_components_from_private_key: ec_components_from_private_key,
        compute_digest,
    },
};

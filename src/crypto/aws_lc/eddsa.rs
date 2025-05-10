//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! EdDSA family of algorithms using [`aws_lc_rs`]

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::Result;
use crate::{Algorithm, DecodingKey, EncodingKey};
use aws_lc_rs::signature::{Ed25519KeyPair, VerificationAlgorithm, ED25519};
use signature::{Error, Signer, Verifier};

pub struct EdDSASigner(Ed25519KeyPair);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        Ok(Self(
            Ed25519KeyPair::from_pkcs8(encoding_key.inner())
                .map_err(|_| crate::errors::ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        Ok(self.0.sign(msg).as_ref().to_vec())
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct EdDSAVerifier(DecodingKey);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        ED25519.verify_sig(self.0.as_bytes(), msg, signature).map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

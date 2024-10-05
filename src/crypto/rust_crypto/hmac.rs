//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using `RustCtypto`'s [`hmac`].

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::Result;
use crate::{Algorithm, HmacSecret};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub struct Hs256(HmacSha256);

impl Hs256 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        let inner = HmacSha256::new_from_slice(&secret)
            .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs256 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs256 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

impl Verifier<Vec<u8>> for Hs256 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs256 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub(crate) struct Hs384(HmacSha384);

impl Hs384 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        let inner = HmacSha384::new_from_slice(&secret)
            .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs384 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs384 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

impl Verifier<Vec<u8>> for Hs384 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs384 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs512(HmacSha512);

impl Hs512 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        let inner = HmacSha512::new_from_slice(&secret)
            .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs512 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs512 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

impl Verifier<Vec<u8>> for Hs512 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs512 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

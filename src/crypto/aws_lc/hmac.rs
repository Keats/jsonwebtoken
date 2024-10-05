//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using [`aws_lc_rs`]

use aws_lc_rs::hmac;
use signature::{Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::Result;
use crate::{Algorithm, HmacSecret};

pub struct Hs256(hmac::Key);

impl Hs256 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, &secret)))
    }
}

impl Signer<Vec<u8>> for Hs256 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs256 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

impl Verifier<Vec<u8>> for Hs256 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, &signature).map_err(|err| signature::Error::from_source(err))
    }
}

impl JwtVerifier for Hs256 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub struct Hs384(hmac::Key);

impl Hs384 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA384, &secret)))
    }
}

impl Signer<Vec<u8>> for Hs384 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs384 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

impl Verifier<Vec<u8>> for Hs384 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, &signature).map_err(|err| signature::Error::from_source(err))
    }
}

impl JwtVerifier for Hs384 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs512(hmac::Key);

impl Hs512 {
    pub(crate) fn new(secret: HmacSecret) -> Result<Self> {
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA512, &secret)))
    }
}

impl Signer<Vec<u8>> for Hs512 {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs512 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

impl Verifier<Vec<u8>> for Hs512 {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, &signature).map_err(|err| signature::Error::from_source(err))
    }
}

impl JwtVerifier for Hs512 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

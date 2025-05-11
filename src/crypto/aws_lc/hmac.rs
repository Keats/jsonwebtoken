//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using [`aws_lc_rs`]

use aws_lc_rs::hmac;
use signature::{Signer, Verifier};

use crate::crypto::utils::{
    try_get_hmac_secret_from_decoding_key, try_get_hmac_secret_from_encoding_key,
};
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::Result;
use crate::{Algorithm, DecodingKey, EncodingKey};

pub struct Hs256Signer(hmac::Key);

impl Hs256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA256,
            try_get_hmac_secret_from_encoding_key(encoding_key)?,
        )))
    }
}

impl Signer<Vec<u8>> for Hs256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub struct Hs256Verifier(hmac::Key);

impl Hs256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA256,
            try_get_hmac_secret_from_decoding_key(decoding_key)?,
        )))
    }
}

impl Verifier<Vec<u8>> for Hs256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, signature).map_err(signature::Error::from_source)
    }
}

impl JwtVerifier for Hs256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub struct Hs384Signer(hmac::Key);

impl Hs384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA384,
            try_get_hmac_secret_from_encoding_key(encoding_key)?,
        )))
    }
}

impl Signer<Vec<u8>> for Hs384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs384Verifier(hmac::Key);

impl Hs384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA384,
            try_get_hmac_secret_from_decoding_key(decoding_key)?,
        )))
    }
}

impl Verifier<Vec<u8>> for Hs384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, signature).map_err(signature::Error::from_source)
    }
}

impl JwtVerifier for Hs384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs512Signer(hmac::Key);

impl Hs512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA512,
            try_get_hmac_secret_from_encoding_key(encoding_key)?,
        )))
    }
}

impl Signer<Vec<u8>> for Hs512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.0, msg).as_ref().to_vec())
    }
}

impl JwtSigner for Hs512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

pub struct Hs512Verifier(hmac::Key);

impl Hs512Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        Ok(Self(hmac::Key::new(
            hmac::HMAC_SHA512,
            try_get_hmac_secret_from_decoding_key(decoding_key)?,
        )))
    }
}

impl Verifier<Vec<u8>> for Hs512Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.0, msg, signature).map_err(signature::Error::from_source)
    }
}

impl JwtVerifier for Hs512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

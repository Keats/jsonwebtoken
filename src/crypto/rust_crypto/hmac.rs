//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using `RustCtypto`'s [`hmac`].

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::try_get_hmac_secret_from_decoding_key;
use crate::encoding::try_get_hmac_secret_from_encoding_key;
use crate::errors::Result;
use crate::{Algorithm, DecodingKey, EncodingKey};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub struct Hs256Signer(HmacSha256);

impl Hs256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        let inner =
            HmacSha256::new_from_slice(try_get_hmac_secret_from_encoding_key(encoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub struct Hs256Verifier(HmacSha256);

impl Hs256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        let inner =
            HmacSha256::new_from_slice(&try_get_hmac_secret_from_decoding_key(decoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Verifier<Vec<u8>> for Hs256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub struct Hs384Signer(HmacSha384);

impl Hs384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        let inner =
            HmacSha384::new_from_slice(try_get_hmac_secret_from_encoding_key(encoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs384Verifier(HmacSha384);

impl Hs384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        let inner =
            HmacSha384::new_from_slice(&try_get_hmac_secret_from_decoding_key(decoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Verifier<Vec<u8>> for Hs384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS384
    }
}

pub struct Hs512Signer(HmacSha512);

impl Hs512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        let inner =
            HmacSha512::new_from_slice(try_get_hmac_secret_from_encoding_key(encoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for Hs512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();
        signer.reset();
        signer.update(msg);

        Ok(signer.finalize().into_bytes().to_vec())
    }
}

impl JwtSigner for Hs512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

pub struct Hs512Verifier(HmacSha512);

impl Hs512Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        let inner =
            HmacSha512::new_from_slice(&try_get_hmac_secret_from_decoding_key(decoding_key)?)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Verifier<Vec<u8>> for Hs512Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        let mut verifier = self.0.clone();
        verifier.reset();
        verifier.update(msg);

        verifier.verify_slice(signature).map_err(|e| signature::Error::from_source(e))
    }
}

impl JwtVerifier for Hs512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS512
    }
}

//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using [`aws_lc_rs`]

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{new_error, ErrorKind, Result};
use crate::{Algorithm, DecodingKey, EncodingKey};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
};
use signature::{Error, Signer, Verifier};

pub struct Es256Signer(EcdsaKeyPair);

impl Es256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, encoding_key.inner())
                .map_err(|_| crate::errors::ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for Es256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        let signature = self.0.sign(&rng, msg).map_err(Error::from_source)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl JwtSigner for Es256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

pub struct Es256Verifier(DecodingKey);

impl Es256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for Es256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        ECDSA_P256_SHA256_FIXED
            .verify_sig(self.0.as_bytes(), msg, signature)
            .map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for Es256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

pub struct Es384Signer(EcdsaKeyPair);

impl Es384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        
        Ok(Self(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, encoding_key.inner())
                .map_err(|_| crate::errors::ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for Es384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        let signature = self.0.sign(&rng, msg).map_err(Error::from_source)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl JwtSigner for Es384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES384
    }
}

pub struct Es384Verifier(DecodingKey);

impl Es384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for Es384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        ECDSA_P384_SHA384_FIXED
            .verify_sig(self.0.as_bytes(), msg, signature)
            .map_err(Error::from_source)?;

        Ok(())
    }
}

impl JwtVerifier for Es384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES384
    }
}

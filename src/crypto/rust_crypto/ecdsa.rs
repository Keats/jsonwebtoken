//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using RustCrypto

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{new_error, ErrorKind, Result};
use crate::{Algorithm, DecodingKey, EncodingKey};
use p256::ecdsa::{
    Signature as Signature256, SigningKey as SigningKey256, VerifyingKey as VerifyingKey256,
};
use p384::ecdsa::{
    Signature as Signature384, SigningKey as SigningKey384, VerifyingKey as VerifyingKey384,
};
use rsa::pkcs8::DecodePrivateKey;
use signature::{Error, Signer, Verifier};

pub struct Es256Signer(SigningKey256);

impl Es256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            SigningKey256::from_pkcs8_der(encoding_key.inner())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for Es256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let signature = self.0.sign_recoverable(msg).map_err(Error::from_source)?.0;
        Ok(signature.to_vec())
    }
}

impl JwtSigner for Es256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

pub struct Es256Verifier(VerifyingKey256);

impl Es256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            VerifyingKey256::from_sec1_bytes(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for Es256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        self.0
            .verify(msg, &Signature256::from_slice(signature).map_err(Error::from_source)?)
            .map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for Es256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

pub struct Es384Signer(SigningKey384);

impl Es384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            SigningKey384::from_pkcs8_der(encoding_key.inner())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for Es384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let signature = self.0.sign_recoverable(msg).map_err(Error::from_source)?.0;
        Ok(signature.to_vec())
    }
}

impl JwtSigner for Es384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES384
    }
}

pub struct Es384Verifier(VerifyingKey384);

impl Es384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            VerifyingKey384::from_sec1_bytes(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for Es384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        self.0
            .verify(msg, &Signature384::from_slice(signature).map_err(Error::from_source)?)
            .map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for Es384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES384
    }
}

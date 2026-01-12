//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using RustCrypto

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use p256::ecdsa::{
    Signature as Signature256, SigningKey as SigningKey256, VerifyingKey as VerifyingKey256,
};
use p384::ecdsa::{
    Signature as Signature384, SigningKey as SigningKey384, VerifyingKey as VerifyingKey384,
};
use p521::ecdsa::{
    Signature as Signature521, SigningKey as SigningKey521, VerifyingKey as VerifyingKey521,
};
use rsa::pkcs8::DecodePrivateKey;
use signature::{Error, Signer, Verifier};

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $signing_key:ty) => {
        pub struct $name($signing_key);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$signing_key>::from_pkcs8_der(encoding_key.inner())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let signature = self.0.sign_recoverable(msg).map_err(Error::from_source)?.0;
                Ok(signature.to_vec())
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $verifying_key:ty, $signature:ty) => {
        pub struct $name($verifying_key);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$verifying_key>::from_sec1_bytes(decoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                self.0
                    .verify(msg, &<$signature>::from_slice(signature).map_err(Error::from_source)?)
                    .map_err(Error::from_source)?;
                Ok(())
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, SigningKey256);
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, SigningKey384);

define_ecdsa_verifier!(Es256Verifier, Algorithm::ES256, VerifyingKey256, Signature256);
define_ecdsa_verifier!(Es384Verifier, Algorithm::ES384, VerifyingKey384, Signature384);

// P521 (ES512) uses a different API - no sign_recoverable
pub struct Es512Signer(SigningKey521);

impl Es512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            SigningKey521::from_bytes(encoding_key.inner().into())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for Es512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let signature: Signature521 = self.0.sign(msg);
        Ok(signature.to_vec())
    }
}

impl JwtSigner for Es512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES512
    }
}

pub struct Es512Verifier(VerifyingKey521);

impl Es512Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            VerifyingKey521::from_sec1_bytes(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for Es512Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        self.0
            .verify(msg, &Signature521::from_slice(signature).map_err(Error::from_source)?)
            .map_err(Error::from_source)?;
        Ok(())
    }
}

impl JwtVerifier for Es512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES512
    }
}

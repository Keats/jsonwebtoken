//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for EdDSA using OpenSSL.

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer as OsslSigner, Verifier as OsslVerifier};
use signature::{Error, Signer, Verifier};

pub struct EdDSASigner(PKey<Private>);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        match PKey::private_key_from_der(encoding_key.inner()) {
            Ok(pkey) => {
                if pkey.id() == Id::ED25519 {
                    Ok(Self(pkey))
                } else {
                    Err(new_error(ErrorKind::InvalidKeyFormat))
                }
            }
            _ => Err(new_error(ErrorKind::InvalidEddsaKey)),
        }
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut signer = OsslSigner::new_without_digest(&self.0).map_err(Error::from_source)?;
        signer.sign_oneshot_to_vec(msg).map_err(Error::from_source)
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct EdDSAVerifier(PKey<Public>);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        let bytes = decoding_key.as_bytes();
        match PKey::public_key_from_der(bytes) {
            Ok(pkey) => {
                if pkey.id() == Id::ED25519 {
                    Ok(Self(pkey))
                } else {
                    Err(new_error(ErrorKind::InvalidKeyFormat))
                }
            }
            _ => Ok(Self(
                PKey::public_key_from_raw_bytes(bytes, Id::ED25519)
                    .map_err(|_| ErrorKind::InvalidEddsaKey)?,
            )),
        }
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        OsslVerifier::new_without_digest(&self.0)
            .and_then(|mut verifier| verifier.verify_oneshot(signature, msg))
            .map_err(Error::from_source)
            .and_then(|valid| if valid { Ok(()) } else { Err(Error::new()) })
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

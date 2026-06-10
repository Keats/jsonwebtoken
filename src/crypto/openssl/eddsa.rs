//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for EdDSA using `openssl`.

use openssl::pkey::{Id, PKey};
use openssl::sign::{Signer as OsslSigner, Verifier as OsslVerifier};
use signature::{Error, Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};

pub struct EdDSASigner(PKey<openssl::pkey::Private>);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        let pkey = PKey::private_key_from_der(encoding_key.inner())
            .map_err(|_| ErrorKind::InvalidEddsaKey)?;
        Ok(Self(pkey))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut signer =
            OsslSigner::new_without_digest(&self.0).map_err(Error::from_source)?;
        signer
            .sign_oneshot_to_vec(msg)
            .map_err(Error::from_source)
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
        if decoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let pkey = PKey::public_key_from_raw_bytes(self.0.as_bytes(), Id::ED25519)
            .map_err(Error::from_source)?;
        let mut verifier =
            OsslVerifier::new_without_digest(&pkey).map_err(Error::from_source)?;
        if verifier
            .verify_oneshot(signature, msg)
            .map_err(Error::from_source)?
        {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

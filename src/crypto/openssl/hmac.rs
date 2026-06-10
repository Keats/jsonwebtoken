//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using `openssl`.

use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer as OsslSigner;
use signature::{Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::Result;
use crate::{Algorithm, DecodingKey, EncodingKey};

macro_rules! define_hmac_signer {
    ($name:ident, $alg:expr, $digest_fn:expr) => {
        pub struct $name(EncodingKey);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                encoding_key.try_get_hmac_secret()?;
                Ok(Self(encoding_key.clone()))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
                let secret = self.0.try_get_hmac_secret().map_err(signature::Error::from_source)?;
                let pkey = PKey::hmac(secret).map_err(signature::Error::from_source)?;
                let mut signer =
                    OsslSigner::new($digest_fn, &pkey).map_err(signature::Error::from_source)?;
                signer.update(msg).map_err(signature::Error::from_source)?;
                signer.sign_to_vec().map_err(signature::Error::from_source)
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_hmac_verifier {
    ($name:ident, $alg:expr, $digest_fn:expr) => {
        pub struct $name(DecodingKey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                decoding_key.try_get_hmac_secret()?;
                Ok(Self(decoding_key.clone()))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(
                &self,
                msg: &[u8],
                signature: &Vec<u8>,
            ) -> std::result::Result<(), signature::Error> {
                let secret =
                    self.0.try_get_hmac_secret().map_err(signature::Error::from_source)?;
                let pkey = PKey::hmac(secret).map_err(signature::Error::from_source)?;
                let mut signer =
                    OsslSigner::new($digest_fn, &pkey).map_err(signature::Error::from_source)?;
                signer.update(msg).map_err(signature::Error::from_source)?;
                let computed = signer.sign_to_vec().map_err(signature::Error::from_source)?;

                if memcmp::eq(&computed, signature) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                }
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_hmac_signer!(Hs256Signer, Algorithm::HS256, MessageDigest::sha256());
define_hmac_signer!(Hs384Signer, Algorithm::HS384, MessageDigest::sha384());
define_hmac_signer!(Hs512Signer, Algorithm::HS512, MessageDigest::sha512());

define_hmac_verifier!(Hs256Verifier, Algorithm::HS256, MessageDigest::sha256());
define_hmac_verifier!(Hs384Verifier, Algorithm::HS384, MessageDigest::sha384());
define_hmac_verifier!(Hs512Verifier, Algorithm::HS512, MessageDigest::sha512());

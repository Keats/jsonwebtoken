//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using [`openssl`]

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result};
use crate::{Algorithm, DecodingKey, EncodingKey};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer as OsslSigner;
use signature::{Error, Signer, Verifier};

macro_rules! define_hmac_signer {
    ($name:ident, $alg:expr, $digest:expr) => {
        pub struct $name(PKey<openssl::pkey::Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                let secret = encoding_key.try_get_hmac_secret()?;

                Ok(Self(PKey::hmac(secret).map_err(|_| ErrorKind::InvalidKeyFormat)?))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                OsslSigner::new($digest, &self.0)
                    .and_then(|mut signer| {
                        signer.update(msg)?;
                        signer.sign_to_vec()
                    })
                    .map_err(Error::from_source)
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
    ($name:ident, $alg:expr, $digest:expr) => {
        pub struct $name(Option<PKey<openssl::pkey::Private>>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                let secret = decoding_key.try_get_hmac_secret()?;
                // Allow empty secret for insecure decode
                if secret.is_empty() {
                    return Ok(Self(None));
                }

                Ok(Self(Some(PKey::hmac(secret).map_err(|_| ErrorKind::InvalidKeyFormat)?)))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let key = self.0.as_ref().ok_or_else(Error::new)?;

                let computed = OsslSigner::new($digest, &key)
                    .and_then(|mut signer| {
                        signer.update(msg)?;
                        signer.sign_to_vec()
                    })
                    .map_err(Error::from_source)?;

                if openssl::memcmp::eq(computed.as_slice(), signature) {
                    Ok(())
                } else {
                    Err(Error::new())
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

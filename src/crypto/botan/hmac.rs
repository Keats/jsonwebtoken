use botan::MsgAuthCode;
use signature::{Error, Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey};
use crate::{EncodingKey, algorithms::AlgorithmFamily};

macro_rules! define_hmac_signer {
    ($name:ident, $alg:expr, $algo:expr) => {
        pub struct $name(Vec<u8>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Hmac {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(encoding_key.try_get_hmac_secret()?.to_vec()))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut auth_code = MsgAuthCode::new($algo).map_err(Error::from_source)?;
                auth_code.set_key(&self.0).map_err(Error::from_source)?;
                auth_code.update(msg).map_err(Error::from_source)?;
                auth_code.finish().map_err(Error::from_source)
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
    ($name:ident, $alg:expr, $algo:expr) => {
        pub struct $name(Vec<u8>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Hmac {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(decoding_key.try_get_hmac_secret()?.to_vec()))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let mut auth_code = MsgAuthCode::new($algo).map_err(Error::from_source)?;
                auth_code.set_key(&self.0).map_err(Error::from_source)?;
                auth_code.update(msg).map_err(Error::from_source)?;
                botan::const_time_compare(
                    &auth_code.finish().map_err(Error::from_source)?,
                    signature,
                )
                .then_some(())
                .ok_or(Error::new())
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_hmac_signer!(Hs256Signer, Algorithm::HS256, "HMAC(SHA-256)");
define_hmac_signer!(Hs384Signer, Algorithm::HS384, "HMAC(SHA-384)");
define_hmac_signer!(Hs512Signer, Algorithm::HS512, "HMAC(SHA-512)");

define_hmac_verifier!(Hs256Verifier, Algorithm::HS256, "HMAC(SHA-256)");
define_hmac_verifier!(Hs384Verifier, Algorithm::HS384, "HMAC(SHA-384)");
define_hmac_verifier!(Hs512Verifier, Algorithm::HS512, "HMAC(SHA-512)");

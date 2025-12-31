//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! RSA family of algorithms using [`openssl`]

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer as OsslSigner, Verifier as OsslVerifier};
use signature::{Error, Signer, Verifier};

macro_rules! define_rsa_signer {
    ($name:ident, $alg:expr, $digest:expr, $padding:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                match PKey::private_key_from_der(encoding_key.inner()) {
                    Ok(pkey) => {
                        if pkey.id() == Id::RSA {
                            Ok(Self(pkey))
                        } else {
                            Err(new_error(ErrorKind::InvalidKeyFormat))
                        }
                    }
                    _ => Err(new_error(ErrorKind::InvalidKeyFormat)),
                }
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                OsslSigner::new($digest, &self.0)
                    .and_then(|mut signer| {
                        signer.set_rsa_padding($padding)?;
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

macro_rules! define_rsa_verifier {
    ($name:ident, $alg:expr, $digest:expr, $padding:expr) => {
        pub struct $name(PKey<Public>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let pkey = match &decoding_key.kind {
                    DecodingKeyKind::SecretOrDer(bytes) => Rsa::public_key_from_der_pkcs1(bytes)
                        .and_then(PKey::from_rsa)
                        .map_err(|_| new_error(ErrorKind::InvalidKeyFormat))?,
                    DecodingKeyKind::RsaModulusExponent { n, e } => {
                        openssl::bn::BigNum::from_slice(n)
                            .and_then(|n_bn| {
                                let e_bn = openssl::bn::BigNum::from_slice(e)?;
                                PKey::from_rsa(Rsa::from_public_components(n_bn, e_bn)?)
                            })
                            .map_err(|_| new_error(ErrorKind::InvalidKeyFormat))?
                    }
                };

                Ok(Self(pkey))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                OsslVerifier::new($digest, &self.0)
                    .and_then(|mut verifier| {
                        verifier.set_rsa_padding($padding)?;
                        if $padding == Padding::PKCS1_PSS {
                            verifier
                                .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                            verifier.set_rsa_mgf1_md($digest)?;
                        }
                        verifier.update(msg)?;
                        verifier.verify(signature)
                    })
                    .map_err(Error::from_source)
                    .and_then(|is_valid| if is_valid { Ok(()) } else { Err(Error::new()) })
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_rsa_signer!(Rsa256Signer, Algorithm::RS256, MessageDigest::sha256(), Padding::PKCS1);
define_rsa_signer!(Rsa384Signer, Algorithm::RS384, MessageDigest::sha384(), Padding::PKCS1);
define_rsa_signer!(Rsa512Signer, Algorithm::RS512, MessageDigest::sha512(), Padding::PKCS1);
define_rsa_signer!(RsaPss256Signer, Algorithm::PS256, MessageDigest::sha256(), Padding::PKCS1_PSS);
define_rsa_signer!(RsaPss384Signer, Algorithm::PS384, MessageDigest::sha384(), Padding::PKCS1_PSS);
define_rsa_signer!(RsaPss512Signer, Algorithm::PS512, MessageDigest::sha512(), Padding::PKCS1_PSS);

define_rsa_verifier!(Rsa256Verifier, Algorithm::RS256, MessageDigest::sha256(), Padding::PKCS1);
define_rsa_verifier!(Rsa384Verifier, Algorithm::RS384, MessageDigest::sha384(), Padding::PKCS1);
define_rsa_verifier!(Rsa512Verifier, Algorithm::RS512, MessageDigest::sha512(), Padding::PKCS1);
define_rsa_verifier!(
    RsaPss256Verifier,
    Algorithm::PS256,
    MessageDigest::sha256(),
    Padding::PKCS1_PSS
);
define_rsa_verifier!(
    RsaPss384Verifier,
    Algorithm::PS384,
    MessageDigest::sha384(),
    Padding::PKCS1_PSS
);
define_rsa_verifier!(
    RsaPss512Verifier,
    Algorithm::PS512,
    MessageDigest::sha512(),
    Padding::PKCS1_PSS
);

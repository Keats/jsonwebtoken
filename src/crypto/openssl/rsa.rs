//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! RSA family of algorithms using `openssl`.

use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer as OsslSigner, Verifier as OsslVerifier};
use signature::{Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};

fn try_sign_rsa(
    encoding_key: &EncodingKey,
    msg: &[u8],
    digest: MessageDigest,
    pss: bool,
) -> std::result::Result<Vec<u8>, signature::Error> {
    let rsa = Rsa::private_key_from_der(encoding_key.inner())
        .map_err(signature::Error::from_source)?;
    let pkey = PKey::from_rsa(rsa).map_err(signature::Error::from_source)?;
    let mut signer =
        OsslSigner::new(digest, &pkey).map_err(signature::Error::from_source)?;

    if pss {
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(signature::Error::from_source)?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(signature::Error::from_source)?;
    }

    signer.update(msg).map_err(signature::Error::from_source)?;
    signer.sign_to_vec().map_err(signature::Error::from_source)
}

fn verify_rsa(
    decoding_key: &DecodingKey,
    msg: &[u8],
    signature: &[u8],
    digest: MessageDigest,
    pss: bool,
) -> std::result::Result<(), signature::Error> {
    let pkey = match decoding_key.kind() {
        DecodingKeyKind::SecretOrDer(bytes) => {
            let rsa = Rsa::public_key_from_der_pkcs1(bytes)
                .map_err(signature::Error::from_source)?;
            PKey::from_rsa(rsa).map_err(signature::Error::from_source)?
        }
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            let bn_n = BigNum::from_slice(n).map_err(signature::Error::from_source)?;
            let bn_e = BigNum::from_slice(e).map_err(signature::Error::from_source)?;
            let rsa = Rsa::from_public_components(bn_n, bn_e)
                .map_err(signature::Error::from_source)?;
            PKey::from_rsa(rsa).map_err(signature::Error::from_source)?
        }
    };

    let mut verifier =
        OsslVerifier::new(digest, &pkey).map_err(signature::Error::from_source)?;

    if pss {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(signature::Error::from_source)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(signature::Error::from_source)?;
    }

    verifier.update(msg).map_err(signature::Error::from_source)?;
    if verifier
        .verify(signature)
        .map_err(signature::Error::from_source)?
    {
        Ok(())
    } else {
        Err(signature::Error::new())
    }
}

macro_rules! define_rsa_signer {
    ($name:ident, $alg:expr, $digest:expr, pss = $pss:expr) => {
        pub struct $name(EncodingKey);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(encoding_key.clone()))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
                try_sign_rsa(&self.0, msg, $digest, $pss)
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
    ($name:ident, $alg:expr, $digest:expr, pss = $pss:expr) => {
        pub struct $name(DecodingKey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(decoding_key.clone()))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(
                &self,
                msg: &[u8],
                signature: &Vec<u8>,
            ) -> std::result::Result<(), signature::Error> {
                verify_rsa(&self.0, msg, signature, $digest, $pss)
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_rsa_signer!(Rsa256Signer, Algorithm::RS256, MessageDigest::sha256(), pss = false);
define_rsa_signer!(Rsa384Signer, Algorithm::RS384, MessageDigest::sha384(), pss = false);
define_rsa_signer!(Rsa512Signer, Algorithm::RS512, MessageDigest::sha512(), pss = false);
define_rsa_signer!(RsaPss256Signer, Algorithm::PS256, MessageDigest::sha256(), pss = true);
define_rsa_signer!(RsaPss384Signer, Algorithm::PS384, MessageDigest::sha384(), pss = true);
define_rsa_signer!(RsaPss512Signer, Algorithm::PS512, MessageDigest::sha512(), pss = true);

define_rsa_verifier!(Rsa256Verifier, Algorithm::RS256, MessageDigest::sha256(), pss = false);
define_rsa_verifier!(Rsa384Verifier, Algorithm::RS384, MessageDigest::sha384(), pss = false);
define_rsa_verifier!(Rsa512Verifier, Algorithm::RS512, MessageDigest::sha512(), pss = false);
define_rsa_verifier!(RsaPss256Verifier, Algorithm::PS256, MessageDigest::sha256(), pss = true);
define_rsa_verifier!(RsaPss384Verifier, Algorithm::PS384, MessageDigest::sha384(), pss = true);
define_rsa_verifier!(RsaPss512Verifier, Algorithm::PS512, MessageDigest::sha512(), pss = true);

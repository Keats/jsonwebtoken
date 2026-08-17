//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ML-DSA family of algorithms (US NIST FIPS 204) using [`aws_lc_rs`]

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use aws_lc_rs::signature::{
    ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
    PqdsaKeyPair, VerificationAlgorithm,
};
use signature::{Error, Signer, Verifier};

macro_rules! define_ml_dsa_signer {
    ($name:ident, $alg:expr, $signing_alg:expr) => {
        pub struct $name(PqdsaKeyPair);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Mldsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    PqdsaKeyPair::from_pkcs8($signing_alg, encoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidKeyFormat)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut signature = vec![0u8; self.0.algorithm().signature_len()];
                let len = self.0.sign(msg, &mut signature).map_err(Error::from_source)?;
                signature.truncate(len);
                Ok(signature)
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ml_dsa_verifier {
    ($name:ident, $alg:expr, $verification_alg:expr) => {
        pub struct $name(DecodingKey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Mldsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(decoding_key.clone()))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                $verification_alg
                    .verify_sig(
                        self.0.try_get_as_bytes().map_err(Error::from_source)?,
                        msg,
                        signature,
                    )
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

define_ml_dsa_signer!(MlDsa44Signer, Algorithm::MLDSA44, &ML_DSA_44_SIGNING);
define_ml_dsa_verifier!(MlDsa44Verifier, Algorithm::MLDSA44, ML_DSA_44);

define_ml_dsa_signer!(MlDsa65Signer, Algorithm::MLDSA65, &ML_DSA_65_SIGNING);
define_ml_dsa_verifier!(MlDsa65Verifier, Algorithm::MLDSA65, ML_DSA_65);

define_ml_dsa_signer!(MlDsa87Signer, Algorithm::MLDSA87, &ML_DSA_87_SIGNING);
define_ml_dsa_verifier!(MlDsa87Verifier, Algorithm::MLDSA87, ML_DSA_87);

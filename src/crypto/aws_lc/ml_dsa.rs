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
                self.0.sign(msg, &mut signature).map_err(Error::from_source)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{sign, verify};
    use crate::jwk::Jwk;
    use aws_lc_rs::signature::{KeyPair, PqdsaSigningAlgorithm};

    fn round_trip(alg: Algorithm, signing_algorithm: &'static PqdsaSigningAlgorithm) {
        let key_pair = PqdsaKeyPair::generate(signing_algorithm).unwrap();
        let pkcs8 = key_pair.to_pkcs8v1().unwrap();
        let encoding_key = EncodingKey::from_mldsa_der(pkcs8.as_ref());
        let decoding_key = DecodingKey::from_mldsa_der(key_pair.public_key().as_ref());

        let msg = b"hello ml-dsa world";
        let signature = sign(msg, &encoding_key, alg).unwrap();

        assert!(verify(&signature, msg, &decoding_key, alg).unwrap());
        assert!(!verify(&signature, b"tampered", &decoding_key, alg).unwrap());
    }

    #[test]
    fn round_trip_test_mldsa44() {
        round_trip(Algorithm::MLDSA44, &ML_DSA_44_SIGNING);
    }

    #[test]
    fn round_trip_test_mldsa65() {
        round_trip(Algorithm::MLDSA65, &ML_DSA_65_SIGNING);
    }

    #[test]
    fn round_trip_test_mldsa87() {
        round_trip(Algorithm::MLDSA87, &ML_DSA_87_SIGNING);
    }

    fn jwk_round_trip(alg: Algorithm, signing_algorithm: &'static PqdsaSigningAlgorithm) {
        let key_pair = PqdsaKeyPair::generate(signing_algorithm).unwrap();
        let pkcs8 = key_pair.to_pkcs8v1().unwrap();
        let encoding_key = EncodingKey::from_mldsa_der(pkcs8.as_ref());
        let decoding_key = DecodingKey::from_mldsa_der(key_pair.public_key().as_ref());

        let jwk = Jwk::from_encoding_key(&encoding_key, alg).unwrap();
        assert!(jwk.is_supported());

        let jwk_from_dec = Jwk::from_decoding_key(&decoding_key, Some(alg)).unwrap();
        assert_eq!(jwk.algorithm, jwk_from_dec.algorithm);

        let decoding_key_from_jwk = DecodingKey::from_jwk(&jwk).unwrap();
        let msg = b"hello ml-dsa jwk";
        let signature = sign(msg, &encoding_key, alg).unwrap();
        assert!(verify(&signature, msg, &decoding_key_from_jwk, alg).unwrap());
    }

    #[test]
    fn jwk_round_trip_test_mldsa44() {
        jwk_round_trip(Algorithm::MLDSA44, &ML_DSA_44_SIGNING);
    }

    #[test]
    fn jwk_round_trip_test_mldsa65() {
        jwk_round_trip(Algorithm::MLDSA65, &ML_DSA_65_SIGNING);
    }

    #[test]
    fn jwk_round_trip_test_mldsa87() {
        jwk_round_trip(Algorithm::MLDSA87, &ML_DSA_87_SIGNING);
    }
}

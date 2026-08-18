//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ML-DSA family of algorithms (US NIST FIPS 204) using the RustCrypto
//! [`ml_dsa`] crate.
//!
//! Signing uses the deterministic variant with an empty context string, as
//! required for JOSE per [RFC 9964](https://datatracker.ietf.org/doc/html/rfc9964).
//! Public keys and signatures use the raw fixed-size encodings mandated by
//! RFC 9964 (i.e. no SPKI/DER wrapping on the verification path).

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use ml_dsa::signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey,
    VerifyingKey, pkcs8::DecodePrivateKey,
};
use signature::{Error, Signer, Verifier};

macro_rules! define_ml_dsa_signer {
    ($name:ident, $alg:expr, $params:ty) => {
        pub struct $name(SigningKey<$params>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Mldsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    SigningKey::<$params>::from_pkcs8_der(encoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidKeyFormat)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                // The `Signer` impl uses the deterministic variant with an
                // empty context, which is what RFC 9964 requires.
                let signature: Signature<$params> = self.0.sign(msg);
                Ok(signature.encode().to_vec())
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
    ($name:ident, $alg:expr, $params:ty) => {
        pub struct $name(VerifyingKey<$params>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Mldsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                // RFC 9964 carries the raw fixed-size public key encoding.
                let encoded =
                    EncodedVerifyingKey::<$params>::try_from(decoding_key.try_get_as_bytes()?)
                        .map_err(|_| ErrorKind::InvalidKeyFormat)?;

                Ok(Self(VerifyingKey::<$params>::decode(&encoded)))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let encoded = EncodedSignature::<$params>::try_from(signature.as_slice())
                    .map_err(Error::from_source)?;
                let signature = Signature::<$params>::decode(&encoded).ok_or_else(Error::new)?;
                self.0.verify(msg, &signature).map_err(Error::from_source)
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_ml_dsa_signer!(MlDsa44Signer, Algorithm::MLDSA44, MlDsa44);
define_ml_dsa_verifier!(MlDsa44Verifier, Algorithm::MLDSA44, MlDsa44);

define_ml_dsa_signer!(MlDsa65Signer, Algorithm::MLDSA65, MlDsa65);
define_ml_dsa_verifier!(MlDsa65Verifier, Algorithm::MLDSA65, MlDsa65);

define_ml_dsa_signer!(MlDsa87Signer, Algorithm::MLDSA87, MlDsa87);
define_ml_dsa_verifier!(MlDsa87Verifier, Algorithm::MLDSA87, MlDsa87);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{sign, verify};
    use crate::jwk::Jwk;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{Generate, pkcs8::EncodePrivateKey};

    macro_rules! round_trip_test {
        ($test_name:ident, $params:ty, $alg:expr) => {
            #[test]
            fn $test_name() {
                // Generate a signing key via the getrandom-backed default RNG.
                let signing_key = SigningKey::<$params>::generate();

                // Private key -> PKCS#8 DER for the EncodingKey.
                let pkcs8 = signing_key.to_pkcs8_der().unwrap();
                let encoding_key = EncodingKey::from_mldsa_der(pkcs8.as_bytes());

                // Public key -> raw fixed-size encoding for the DecodingKey (RFC 9964).
                let raw_pub = signing_key.verifying_key().encode();
                let decoding_key = DecodingKey::from_mldsa_der(&raw_pub);

                let msg = b"hello ml-dsa world";
                let sig = sign(msg, &encoding_key, $alg).unwrap();

                assert!(verify(&sig, msg, &decoding_key, $alg).unwrap());
                // A tampered message must not verify.
                assert!(!verify(&sig, b"tampered", &decoding_key, $alg).unwrap());
            }
        };
    }

    round_trip_test!(round_trip_ml_dsa_44, MlDsa44, Algorithm::MLDSA44);
    round_trip_test!(round_trip_ml_dsa_65, MlDsa65, Algorithm::MLDSA65);
    round_trip_test!(round_trip_ml_dsa_87, MlDsa87, Algorithm::MLDSA87);

    macro_rules! jwk_round_trip_test {
        ($test_name:ident, $params:ty, $alg:expr) => {
            #[test]
            fn $test_name() {
                let signing_key = SigningKey::<$params>::generate();
                let pkcs8 = signing_key.to_pkcs8_der().unwrap();
                let encoding_key = EncodingKey::from_mldsa_der(pkcs8.as_bytes());

                // EncodingKey -> AKP JWK (derives `pub` via KeyUtils).
                let jwk = Jwk::from_encoding_key(&encoding_key, $alg).unwrap();
                assert!(jwk.is_supported());

                // The AKP JWK derived from the public part of the decoding key
                // must be identical.
                let raw_pub = signing_key.verifying_key().encode();
                let decoding_key = DecodingKey::from_mldsa_der(&raw_pub);
                let jwk_from_dec = Jwk::from_decoding_key(&decoding_key, Some($alg)).unwrap();
                assert_eq!(jwk.algorithm, jwk_from_dec.algorithm);

                // JWK -> DecodingKey -> verify a signature made with the encoding key.
                let decoding_key_from_jwk = DecodingKey::from_jwk(&jwk).unwrap();
                let msg = b"hello ml-dsa jwk";
                let sig = sign(msg, &encoding_key, $alg).unwrap();
                assert!(verify(&sig, msg, &decoding_key_from_jwk, $alg).unwrap());
            }
        };
    }

    jwk_round_trip_test!(jwk_round_trip_ml_dsa_44, MlDsa44, Algorithm::MLDSA44);
    jwk_round_trip_test!(jwk_round_trip_ml_dsa_65, MlDsa65, Algorithm::MLDSA65);
    jwk_round_trip_test!(jwk_round_trip_ml_dsa_87, MlDsa87, Algorithm::MLDSA87);
}

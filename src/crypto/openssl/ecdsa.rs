//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using `openssl`.

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::{Signer as OsslSigner, Verifier as OsslVerifier};
use signature::{Error, Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $digest:expr, $field_size:expr) => {
        pub struct $name(PKey<openssl::pkey::Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let pkey = PKey::private_key_from_der(encoding_key.inner())
                    .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
                Ok(Self(pkey))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut signer =
                    OsslSigner::new($digest, &self.0).map_err(Error::from_source)?;
                signer.update(msg).map_err(Error::from_source)?;
                let der_sig = signer.sign_to_vec().map_err(Error::from_source)?;

                // Convert DER-encoded signature to fixed-length (r || s) format for JWT
                let ecdsa_sig = EcdsaSig::from_der(&der_sig).map_err(Error::from_source)?;
                let r = ecdsa_sig
                    .r()
                    .to_vec_padded($field_size)
                    .map_err(Error::from_source)?;
                let s = ecdsa_sig
                    .s()
                    .to_vec_padded($field_size)
                    .map_err(Error::from_source)?;

                let mut fixed_sig = Vec::with_capacity($field_size * 2);
                fixed_sig.extend_from_slice(&r);
                fixed_sig.extend_from_slice(&s);
                Ok(fixed_sig)
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $digest:expr, $nid:expr, $field_size:expr) => {
        pub struct $name(DecodingKey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
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
            ) -> std::result::Result<(), Error> {
                // Reconstruct EC public key from SEC1 uncompressed point bytes
                let group = EcGroup::from_curve_name($nid).map_err(Error::from_source)?;
                let mut ctx = BigNumContext::new().map_err(Error::from_source)?;
                let point = EcPoint::from_bytes(&group, self.0.as_bytes(), &mut ctx)
                    .map_err(Error::from_source)?;
                let ec_key =
                    EcKey::from_public_key(&group, &point).map_err(Error::from_source)?;
                let pkey = PKey::from_ec_key(ec_key).map_err(Error::from_source)?;

                // Convert fixed-length (r || s) signature to DER format
                let (r_bytes, s_bytes) = signature.split_at($field_size);
                let r = BigNum::from_slice(r_bytes).map_err(Error::from_source)?;
                let s = BigNum::from_slice(s_bytes).map_err(Error::from_source)?;
                let ecdsa_sig =
                    EcdsaSig::from_private_components(r, s).map_err(Error::from_source)?;
                let der_sig = ecdsa_sig.to_der().map_err(Error::from_source)?;

                let mut verifier =
                    OsslVerifier::new($digest, &pkey).map_err(Error::from_source)?;
                verifier.update(msg).map_err(Error::from_source)?;
                if verifier.verify(&der_sig).map_err(Error::from_source)? {
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

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, MessageDigest::sha256(), 32);
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, MessageDigest::sha384(), 48);

define_ecdsa_verifier!(Es256Verifier, Algorithm::ES256, MessageDigest::sha256(), Nid::X9_62_PRIME256V1, 32);
define_ecdsa_verifier!(Es384Verifier, Algorithm::ES384, MessageDigest::sha384(), Nid::SECP384R1, 48);

//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using [`openssl`]

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use signature::{Error, Signer, Verifier};

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $digest:expr, $byte_len:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                match PKey::private_key_from_der(encoding_key.inner()) {
                    Ok(pkey) => {
                        if pkey.id() == Id::EC {
                            Ok(Self(pkey))
                        } else {
                            Err(new_error(ErrorKind::InvalidKeyFormat))
                        }
                    }
                    _ => Err(new_error(ErrorKind::InvalidEcdsaKey)),
                }
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                use openssl::sign::Signer as OsslSigner;

                let ecdsa_sig = OsslSigner::new($digest, &self.0)
                    .and_then(|mut signer| {
                        signer.update(msg)?;
                        let der_sig = signer.sign_to_vec()?;
                        EcdsaSig::from_der(&der_sig)
                    })
                    .map_err(Error::from_source)?;

                let r = ecdsa_sig.r().to_vec();
                let s = ecdsa_sig.s().to_vec();

                let byte_len = $byte_len;
                let mut signature = vec![0u8; byte_len * 2];
                let r_padding = byte_len.saturating_sub(r.len());
                let s_padding = byte_len.saturating_sub(s.len());
                signature[r_padding..byte_len].copy_from_slice(&r);
                signature[byte_len + s_padding..].copy_from_slice(&s);

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

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $digest:expr, $nid:expr) => {
        pub struct $name(PKey<Public>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let key_bytes = decoding_key.as_bytes();

                if let Ok(pkey) = PKey::public_key_from_der(key_bytes) {
                    if pkey.id() == Id::EC {
                        return Ok(Self(pkey));
                    } else {
                        return Err(new_error(ErrorKind::InvalidKeyFormat));
                    }
                }

                // Fall back to raw EC point format
                let pkey = BigNumContext::new()
                    .and_then(|ref mut ctx| {
                        let group = EcGroup::from_curve_name($nid)?;
                        let point = EcPoint::from_bytes(&group, key_bytes, ctx)?;
                        let ec_key = EcKey::from_public_key(&group, &point)?;
                        PKey::from_ec_key(ec_key)
                    })
                    .map_err(|_| new_error(ErrorKind::InvalidEcdsaKey))?;

                Ok(Self(pkey))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                use openssl::sign::Verifier as OsslVerifier;

                let byte_len = signature.len() / 2;

                openssl::bn::BigNum::from_slice(&signature[..byte_len])
                    .and_then(|r| {
                        let s = openssl::bn::BigNum::from_slice(&signature[byte_len..])?;
                        let ecdsa_sig = EcdsaSig::from_private_components(r, s)?;
                        let der_sig = ecdsa_sig.to_der()?;

                        let mut verifier = OsslVerifier::new($digest, &self.0)?;
                        verifier.update(msg)?;
                        verifier.verify(&der_sig)
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

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, MessageDigest::sha256(), 32);
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, MessageDigest::sha384(), 48);

define_ecdsa_verifier!(
    Es256Verifier,
    Algorithm::ES256,
    MessageDigest::sha256(),
    Nid::X9_62_PRIME256V1
);
define_ecdsa_verifier!(Es384Verifier, Algorithm::ES384, MessageDigest::sha384(), Nid::SECP384R1);

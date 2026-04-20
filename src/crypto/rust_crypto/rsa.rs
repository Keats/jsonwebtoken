//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! RSA family of algorithms using RustCrypto.

// Use the hash types re-exported by `rsa` so this backend stays in the same
// digest ecosystem as the 0.10 RC line without a crate-wide sha2 migration.
use rsa::{
    BoxedUint, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::AssociatedOid,
    sha2::{
        Sha256, Sha384, Sha512,
        digest::{Digest, FixedOutputReset},
    },
    traits::SignatureScheme,
};
use signature::{Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};

fn to_boxed_uint(bytes: &[u8]) -> std::result::Result<BoxedUint, signature::Error> {
    let bits_precision =
        u32::try_from(bytes.len().saturating_mul(8)).map_err(signature::Error::from_source)?;
    BoxedUint::from_be_slice(bytes, bits_precision).map_err(signature::Error::from_source)
}

fn try_sign_rsa<H>(
    encoding_key: &EncodingKey,
    msg: &[u8],
    pss: bool,
) -> std::result::Result<Vec<u8>, signature::Error>
where
    H: Digest + AssociatedOid + FixedOutputReset,
{
    let mut rng = rand10::rng();
    let private_key = RsaPrivateKey::from_pkcs1_der(encoding_key.inner())
        .map_err(signature::Error::from_source)?;
    let digest = H::digest(msg);

    let signature = if pss {
        private_key.sign_with_rng(&mut rng, Pss::<H>::new(), digest.as_ref())
    } else {
        private_key.sign_with_rng(&mut rng, Pkcs1v15Sign::new::<H>(), digest.as_ref())
    }
    .map_err(signature::Error::from_source)?;

    Ok(signature)
}

fn verify_rsa<S: SignatureScheme, H: Digest>(
    scheme: S,
    decoding_key: &DecodingKey,
    msg: &[u8],
    signature: &[u8],
) -> std::result::Result<(), signature::Error> {
    let digest = H::digest(msg);

    match decoding_key.kind() {
        DecodingKeyKind::SecretOrDer(bytes) => {
            RsaPublicKey::from_pkcs1_der(bytes)
                .map_err(signature::Error::from_source)?
                .verify(scheme, digest.as_ref(), signature)
                .map_err(signature::Error::from_source)?;
        }
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            RsaPublicKey::new(to_boxed_uint(n)?, to_boxed_uint(e)?)
                .map_err(signature::Error::from_source)?
                .verify(scheme, digest.as_ref(), signature)
                .map_err(signature::Error::from_source)?;
        }
    };

    Ok(())
}

macro_rules! define_rsa_signer {
    ($name:ident, $alg:expr, $hash:ty, pss = $pss:expr) => {
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
                try_sign_rsa::<$hash>(&self.0, msg, $pss)
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
    ($name:ident, $alg:expr, $hash:ty, pss = $pss:expr) => {
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
                if $pss {
                    verify_rsa::<_, $hash>(Pss::<$hash>::new(), &self.0, msg, signature)
                } else {
                    verify_rsa::<_, $hash>(Pkcs1v15Sign::new::<$hash>(), &self.0, msg, signature)
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

define_rsa_signer!(Rsa256Signer, Algorithm::RS256, Sha256, pss = false);
define_rsa_signer!(Rsa384Signer, Algorithm::RS384, Sha384, pss = false);
define_rsa_signer!(Rsa512Signer, Algorithm::RS512, Sha512, pss = false);
define_rsa_signer!(RsaPss256Signer, Algorithm::PS256, Sha256, pss = true);
define_rsa_signer!(RsaPss384Signer, Algorithm::PS384, Sha384, pss = true);
define_rsa_signer!(RsaPss512Signer, Algorithm::PS512, Sha512, pss = true);

define_rsa_verifier!(Rsa256Verifier, Algorithm::RS256, Sha256, pss = false);
define_rsa_verifier!(Rsa384Verifier, Algorithm::RS384, Sha384, pss = false);
define_rsa_verifier!(Rsa512Verifier, Algorithm::RS512, Sha512, pss = false);
define_rsa_verifier!(RsaPss256Verifier, Algorithm::PS256, Sha256, pss = true);
define_rsa_verifier!(RsaPss384Verifier, Algorithm::PS384, Sha384, pss = true);
define_rsa_verifier!(RsaPss512Verifier, Algorithm::PS512, Sha512, pss = true);

use botan::{MPI, Privkey, Pubkey};
use signature::{Error, Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey};
use crate::{EncodingKey, algorithms::AlgorithmFamily};

macro_rules! define_rsa_signer {
    ($name:ident, $alg:expr, $padding:expr) => {
        pub struct $name(Privkey);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    Privkey::load_rsa_pkcs1(encoding_key.inner())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut rng =
                    botan::RandomNumberGenerator::new_system().map_err(Error::from_source)?;
                let mut signer =
                    botan::Signer::new(&self.0, $padding).map_err(Error::from_source)?;
                signer.update(msg).map_err(Error::from_source)?;
                signer.finish(&mut rng).map_err(Error::from_source)
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
    ($name:ident, $alg:expr, $padding:expr) => {
        pub struct $name(Pubkey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let pubkey = match &decoding_key.kind {
                    DecodingKeyKind::SecretOrDer(items) => Pubkey::load_rsa_pkcs1(&items),
                    DecodingKeyKind::RsaModulusExponent { n, e } => {
                        Pubkey::load_rsa(&MPI::new_from_bytes(&n)?, &MPI::new_from_bytes(&e)?)
                    }
                }
                .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;

                Ok(Self(pubkey))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let mut verifier =
                    botan::Verifier::new(&self.0, $padding).map_err(Error::from_source)?;
                verifier.update(msg).map_err(Error::from_source)?;
                verifier
                    .finish(&signature)
                    .map_err(Error::from_source)?
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

define_rsa_signer!(Rsa256Signer, Algorithm::RS256, "PKCS1v15(SHA-256)");
define_rsa_signer!(Rsa384Signer, Algorithm::RS384, "PKCS1v15(SHA-384)");
define_rsa_signer!(Rsa512Signer, Algorithm::RS512, "PKCS1v15(SHA-512)");
define_rsa_signer!(RsaPss256Signer, Algorithm::PS256, "PSS(SHA-256)");
define_rsa_signer!(RsaPss384Signer, Algorithm::PS384, "PSS(SHA-384)");
define_rsa_signer!(RsaPss512Signer, Algorithm::PS512, "PSS(SHA-512)");

define_rsa_verifier!(Rsa256Verifier, Algorithm::RS256, "PKCS1v15(SHA-256)");
define_rsa_verifier!(Rsa384Verifier, Algorithm::RS384, "PKCS1v15(SHA-384)");
define_rsa_verifier!(Rsa512Verifier, Algorithm::RS512, "PKCS1v15(SHA-512)");
define_rsa_verifier!(RsaPss256Verifier, Algorithm::PS256, "PSS(SHA-256)");
define_rsa_verifier!(RsaPss384Verifier, Algorithm::PS384, "PSS(SHA-384)");
define_rsa_verifier!(RsaPss512Verifier, Algorithm::PS512, "PSS(SHA-512)");

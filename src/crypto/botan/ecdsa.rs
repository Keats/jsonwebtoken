use botan::{MPI, Privkey, Pubkey};
use signature::{Error, Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey};
use crate::{EncodingKey, algorithms::AlgorithmFamily};

/// extract x and y from some DER bytes
fn extract_points(bytes: &[u8], curve: &str) -> Result<(MPI, MPI)> {
    let point_length = match curve {
        "secp256r1" => 32,
        "secp384r1" => 48,
        _ => unreachable!(),
    };

    if bytes.len() != 1 + 2 * point_length || bytes[0] != 4 {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }

    let x_bytes = MPI::new_from_bytes(&bytes[1..point_length + 1])?;
    let y_bytes = MPI::new_from_bytes(&bytes[point_length + 1..point_length * 2 + 1])?;

    Ok((x_bytes, y_bytes))
}

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $padding:expr) => {
        pub struct $name(Privkey);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    Privkey::load_der(encoding_key.inner())
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

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $padding:expr, $curve:expr) => {
        pub struct $name(Pubkey);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let (x_bytes, y_bytes) = extract_points(decoding_key.as_bytes(), $curve)?;

                Ok(Self(
                    Pubkey::load_ecdsa(&x_bytes, &y_bytes, $curve)
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
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

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, "SHA-256");
define_ecdsa_verifier!(Es256Verifier, Algorithm::ES256, "SHA-256", "secp256r1");

define_ecdsa_signer!(Es384Signer, Algorithm::ES384, "SHA-384");
define_ecdsa_verifier!(Es384Verifier, Algorithm::ES384, "SHA-384", "secp384r1");

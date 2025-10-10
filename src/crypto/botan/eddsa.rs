use botan::{Privkey, Pubkey};
use signature::{Error, Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey};
use crate::{EncodingKey, algorithms::AlgorithmFamily};

pub struct EdDSASigner(Privkey);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(Privkey::load_der(encoding_key.inner()).map_err(|_| ErrorKind::InvalidEddsaKey)?))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::from_source)?;
        let mut signer = botan::Signer::new(&self.0, "Pure").map_err(Error::from_source)?;
        signer.update(msg).map_err(Error::from_source)?;
        signer.finish(&mut rng).map_err(Error::from_source)
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct EdDSAVerifier(Pubkey);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            Pubkey::load_ed25519(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let mut verifier = botan::Verifier::new(&self.0, "Pure").map_err(Error::from_source)?;
        verifier.update(msg).map_err(Error::from_source)?;
        verifier.finish(signature).map_err(Error::from_source)?.then_some(()).ok_or(Error::new())
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

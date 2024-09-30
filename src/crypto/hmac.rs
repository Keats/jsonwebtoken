use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use signature::Signer;

use crate::errors::Result;
use crate::serialization::{b64_decode, b64_encode};
use crate::Algorithm;

use super::JwtSigner;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub(crate) struct HmacSha256Trait(HmacSha256);

impl HmacSha256Trait {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let inner = HmacSha256::new_from_slice(key)
            .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;

        Ok(Self(inner))
    }
}

impl Signer<Vec<u8>> for HmacSha256Trait {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let mut signer = self.0.clone();

        Ok(signer.sign(msg))
    }
}

impl JwtSigner for HmacSha256Trait {
    fn algorithm(&self) -> Algorithm {
        Algorithm::HS256
    }
}

pub(crate) fn sign_hmac(alg: Algorithm, key: &[u8], message: &[u8]) -> Result<String> {
    let mut hmac = create_hmac(alg, key)?;
    let digest = hmac.sign(message);
    Ok(b64_encode(digest))
}

pub(crate) fn hmac_verify(
    alg: Algorithm,
    signature: &str,
    key: &[u8],
    message: &[u8],
) -> Result<bool> {
    let mut hmac = create_hmac(alg, key)?;
    let signature = b64_decode(signature)?;
    Ok(hmac.verify(&signature, message))
}

fn create_hmac(alg: Algorithm, key: &[u8]) -> Result<Box<dyn HmacAlgorithm>> {
    let hmac: Box<dyn HmacAlgorithm> = match alg {
        Algorithm::HS256 => {
            let sha256 = HmacSha256::new_from_slice(key)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            Box::new(sha256)
        }
        Algorithm::HS384 => {
            let sha384 = HmacSha384::new_from_slice(key)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            Box::new(sha384)
        }
        Algorithm::HS512 => {
            let sha512 = HmacSha512::new_from_slice(key)
                .map_err(|_e| crate::errors::ErrorKind::InvalidKeyFormat)?;
            Box::new(sha512)
        }
        _ => {
            return Err(crate::errors::new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }
    };
    Ok(hmac)
}

trait HmacAlgorithm {
    fn sign(&mut self, message: &[u8]) -> Vec<u8>;
    fn verify(&mut self, signature: &[u8], message: &[u8]) -> bool;
}

impl HmacAlgorithm for Box<dyn HmacAlgorithm + '_> {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        (**self).sign(message)
    }

    fn verify(&mut self, signature: &[u8], message: &[u8]) -> bool {
        (**self).verify(signature, message)
    }
}

impl HmacAlgorithm for HmacSha256 {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.reset();
        self.update(message);
        self.clone().finalize().into_bytes().to_vec()
    }
    fn verify(&mut self, signature: &[u8], message: &[u8]) -> bool {
        self.reset();
        self.update(message);
        self.clone().verify_slice(signature).is_ok()
    }
}

impl HmacAlgorithm for HmacSha384 {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.reset();
        self.update(message);
        self.clone().finalize().into_bytes().to_vec()
    }
    fn verify(&mut self, signature: &[u8], message: &[u8]) -> bool {
        self.reset();
        self.update(message);
        self.clone().verify_slice(signature).is_ok()
    }
}

impl HmacAlgorithm for HmacSha512 {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.reset();
        self.update(message);
        self.clone().finalize().into_bytes().to_vec()
    }

    fn verify(&mut self, signature: &[u8], message: &[u8]) -> bool {
        self.reset();
        self.update(message);
        self.clone().verify_slice(signature).is_ok()
    }
}

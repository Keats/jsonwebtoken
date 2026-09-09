use crate::Algorithm;
use signature::{Error, Signer, Verifier};
use crate::crypto::{JwtVerifier,JwtSigner};

pub struct NoEncryption;

impl NoEncryption {
    pub fn new() -> Self {
        NoEncryption
    }
}

impl Verifier<Vec<u8>> for NoEncryption {
    fn verify(&self, _msg: &[u8], _signature: &Vec<u8>) -> Result<(), Error> {
        Ok(())
    }
}

impl Signer<Vec<u8>> for NoEncryption {
    fn try_sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        Ok(vec![])
    }
}

impl JwtSigner for NoEncryption {
    fn algorithm(&self) -> Algorithm {
        Algorithm::None
    }
}


impl JwtVerifier for NoEncryption {
    fn algorithm(&self) -> Algorithm {
        Algorithm::None
    }
}
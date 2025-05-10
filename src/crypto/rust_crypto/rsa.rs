//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! RSA family of algorithms using [`aws_lc_rs`]

use hmac::digest::FixedOutputReset;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs1v15::SigningKey,
    pkcs8::AssociatedOid,
    pss::BlindedSigningKey,
    traits::SignatureScheme,
    BigUint, Pkcs1v15Sign, Pss, RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{new_error, ErrorKind, Result};
use crate::{Algorithm, DecodingKey, EncodingKey};

fn try_sign_rsa<H>(
    encoding_key: &EncodingKey,
    msg: &[u8],
    pss: bool,
) -> std::result::Result<Vec<u8>, signature::Error>
where
    H: Digest + AssociatedOid + FixedOutputReset,
{
    let mut rng = rand::thread_rng();
    if pss {
        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(encoding_key.inner())
            .map_err(signature::Error::from_source)?;
        let signing_key = BlindedSigningKey::<H>::new(private_key);
        Ok(signing_key.sign_with_rng(&mut rng, msg).to_vec())
    } else {
        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(encoding_key.inner())
            .map_err(signature::Error::from_source)?;
        let signing_key = SigningKey::<H>::new(private_key);
        Ok(signing_key.sign_with_rng(&mut rng, msg).to_vec())
    }
}

fn verify_rsa<S: SignatureScheme, H: Digest + AssociatedOid>(
    scheme: S,
    decoding_key: &DecodingKey,
    msg: &[u8],
    signature: &[u8],
) -> std::result::Result<(), signature::Error> {
    let digest = H::digest(msg);

    match &decoding_key.kind {
        DecodingKeyKind::SecretOrDer(bytes) => {
            RsaPublicKey::from_pkcs1_der(bytes)
                .map_err(signature::Error::from_source)?
                .verify(scheme, &digest, signature)
                .map_err(signature::Error::from_source)?;
        }
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))?
                .verify(scheme, &digest, signature)
                .map_err(signature::Error::from_source)?;
        }
    };

    Ok(())
}

pub struct Rsa256Signer(EncodingKey);

impl Rsa256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for Rsa256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha256>(&self.0, msg, false)
    }
}

impl JwtSigner for Rsa256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS256
    }
}

pub struct Rsa256Verifier(DecodingKey);

impl Rsa256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for Rsa256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha256>(Pkcs1v15Sign::new::<Sha256>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for Rsa256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS256
    }
}

pub struct Rsa384Signer(EncodingKey);

impl Rsa384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for Rsa384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha384>(&self.0, msg, false)
    }
}

impl JwtSigner for Rsa384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS384
    }
}

pub struct Rsa384Verifier(DecodingKey);

impl Rsa384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for Rsa384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha384>(Pkcs1v15Sign::new::<Sha384>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for Rsa384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS384
    }
}

pub struct Rsa512Signer(EncodingKey);

impl Rsa512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for Rsa512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha512>(&self.0, msg, false)
    }
}

impl JwtSigner for Rsa512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS512
    }
}

pub struct Rsa512Verifier(DecodingKey);

impl Rsa512Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for Rsa512Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha512>(Pkcs1v15Sign::new::<Sha512>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for Rsa512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS512
    }
}

pub struct RsaPss256Signer(EncodingKey);

impl RsaPss256Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for RsaPss256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha256>(&self.0, msg, true)
    }
}

impl JwtSigner for RsaPss256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS256
    }
}

pub struct RsaPss256Verifier(DecodingKey);

impl RsaPss256Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for RsaPss256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha256>(Pss::new::<Sha256>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for RsaPss256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS256
    }
}

pub struct RsaPss384Signer(EncodingKey);

impl RsaPss384Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for RsaPss384Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha384>(&self.0, msg, true)
    }
}

impl JwtSigner for RsaPss384Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS384
    }
}

pub struct RsaPss384Verifier(DecodingKey);

impl RsaPss384Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for RsaPss384Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha384>(Pss::new::<Sha384>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for RsaPss384Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS384
    }
}

pub struct RsaPss512Signer(EncodingKey);

impl RsaPss512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(encoding_key.clone()))
    }
}

impl Signer<Vec<u8>> for RsaPss512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        try_sign_rsa::<Sha512>(&self.0, msg, true)
    }
}

impl JwtSigner for RsaPss512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS512
    }
}

pub struct RsaPss512Verifier(DecodingKey);

impl RsaPss512Verifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family != AlgorithmFamily::Rsa {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(decoding_key.clone()))
    }
}

impl Verifier<Vec<u8>> for RsaPss512Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        verify_rsa::<_, Sha512>(Pss::new::<Sha512>(), &self.0, msg, signature)
    }
}

impl JwtVerifier for RsaPss512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::PS512
    }
}

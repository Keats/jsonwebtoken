//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! RSA family of algorithms using [`aws_lc_rs`]

use aws_lc_rs::{rand, signature as crypto_sig};
use signature::{Signer, Verifier};

use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::decoding::DecodingKeyKind;
use crate::errors::{new_error, ErrorKind, Result};
use crate::{Algorithm, DecodingKey, EncodingKey};

/// Try to sign the `message` using an `RSA` `algorithm`.
fn try_sign_rsa(
    algorithm: &'static dyn crypto_sig::RsaEncoding,
    encoding_key: &EncodingKey,
    msg: &[u8],
) -> std::result::Result<Vec<u8>, signature::Error> {
    let key_pair = crypto_sig::RsaKeyPair::from_der(encoding_key.inner())
        .map_err(|err| signature::Error::from_source(err))?;

    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(algorithm, &rng, msg, &mut signature)
        .map_err(|err| signature::Error::from_source(err))?;

    Ok(signature)
}

/// Return a `aws_lc_rs` RSA public key from a [`DecodingKey`]
///
/// # Errors
///
/// - If `decoding_key` is not from the RSA family.
fn verify_rsa(
    algorithm: &'static crypto_sig::RsaParameters,
    decoding_key: &DecodingKey,
    msg: &[u8],
    signature: &[u8],
) -> std::result::Result<(), signature::Error> {
    match &decoding_key.kind {
        DecodingKeyKind::SecretOrDer(bytes) => {
            let public_key = crypto_sig::UnparsedPublicKey::new(algorithm, bytes);
            public_key.verify(msg, signature).map_err(|err| signature::Error::from_source(err))?;
        }
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            let public_key = crypto_sig::RsaPublicKeyComponents { n, e };
            public_key
                .verify(algorithm, msg, &signature)
                .map_err(|err| signature::Error::from_source(err))?;
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
        try_sign_rsa(&crypto_sig::RSA_PKCS1_SHA256, &self.0, msg)
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
        verify_rsa(&crypto_sig::RSA_PKCS1_2048_8192_SHA256, &self.0, msg, signature)
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
        try_sign_rsa(&crypto_sig::RSA_PKCS1_SHA384, &self.0, msg)
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
        verify_rsa(&crypto_sig::RSA_PKCS1_2048_8192_SHA384, &self.0, msg, signature)
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
        try_sign_rsa(&crypto_sig::RSA_PKCS1_SHA512, &self.0, msg)
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
        verify_rsa(&crypto_sig::RSA_PKCS1_2048_8192_SHA512, &self.0, msg, signature)
    }
}

impl JwtVerifier for Rsa512Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS512
    }
}

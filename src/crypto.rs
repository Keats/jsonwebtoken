use std::sync::Arc;

use base64;
use ring::constant_time::verify_slices_are_equal;
use ring::{digest, hmac, rand, signature};
use std::str::FromStr;
use untrusted;

use errors::{new_error, Error, ErrorKind, Result};

/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// ECDSA using SHA-256
    ES256,

    /// ECDSA using SHA-384
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            _ => Err(new_error(ErrorKind::InvalidAlgorithmName)),
        }
    }
}

/// The actual HS signing + encoding
fn sign_hmac<K: Key>(
    alg: &'static digest::Algorithm,
    key: K,
    signing_input: &str,
) -> Result<String> {
    let signing_key = hmac::SigningKey::new(alg, key.as_ref());
    let digest = hmac::sign(&signing_key, signing_input.as_bytes());

    Ok(base64::encode_config::<hmac::Signature>(&digest, base64::URL_SAFE_NO_PAD))
}

/// The actual ECDSA signing + encoding
fn sign_ecdsa<K: Key>(
    alg: &'static signature::EcdsaSigningAlgorithm,
    key: K,
    signing_input: &str,
) -> Result<String> {
    let signing_key = match key.format() {
        KeyFormat::PKCS8 => {
            signature::EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(key.as_ref()))?
        }
        _ => {
            return Err(ErrorKind::InvalidKeyFormat)?;
        }
    };

    let rng = rand::SystemRandom::new();
    let sig = signing_key.sign(&rng, untrusted::Input::from(signing_input.as_bytes()))?;
    Ok(base64::encode_config(&sig, base64::URL_SAFE_NO_PAD))
}

/// The actual RSA signing + encoding
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
fn sign_rsa<K: Key>(
    alg: &'static signature::RsaEncoding,
    key: K,
    signing_input: &str,
) -> Result<String> {
    let key_bytes = untrusted::Input::from(key.as_ref());
    let key_pair = match key.format() {
        KeyFormat::DER => {
            signature::RsaKeyPair::from_der(key_bytes).map_err(|_| ErrorKind::InvalidRsaKey)?
        }
        KeyFormat::PKCS8 => {
            signature::RsaKeyPair::from_pkcs8(key_bytes).map_err(|_| ErrorKind::InvalidRsaKey)?
        }
        _ => {
            return Err(ErrorKind::InvalidKeyFormat)?;
        }
    };

    let key_pair = Arc::new(key_pair);
    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|_| ErrorKind::InvalidRsaKey)?;

    Ok(base64::encode_config::<[u8]>(&signature, base64::URL_SAFE_NO_PAD))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign<K: Key>(signing_input: &str, key: K, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(&digest::SHA256, key, signing_input),
        Algorithm::HS384 => sign_hmac(&digest::SHA384, key, signing_input),
        Algorithm::HS512 => sign_hmac(&digest::SHA512, key, signing_input),

        Algorithm::ES256 => {
            sign_ecdsa(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, key, signing_input)
        }
        Algorithm::ES384 => {
            sign_ecdsa(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, key, signing_input)
        }

        Algorithm::RS256 => sign_rsa(&signature::RSA_PKCS1_SHA256, key, signing_input),
        Algorithm::RS384 => sign_rsa(&signature::RSA_PKCS1_SHA384, key, signing_input),
        Algorithm::RS512 => sign_rsa(&signature::RSA_PKCS1_SHA512, key, signing_input),
    }
}

/// See Ring docs for more details
fn verify_ring(
    alg: &dyn signature::VerificationAlgorithm,
    signature: &str,
    signing_input: &str,
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
    let public_key_der = untrusted::Input::from(key);
    let message = untrusted::Input::from(signing_input.as_bytes());
    let expected_signature = untrusted::Input::from(signature_bytes.as_slice());

    let res = signature::verify(alg, public_key_der, message, expected_signature);

    Ok(res.is_ok())
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA.
///
/// Only use this function if you want to do something other than JWT.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `signing_input` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    signing_input: &str,
    public_key: &[u8],
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the data with the key and compare if they are equal
            let signed = sign(signing_input, Hmac::from(&public_key), algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        }
        Algorithm::ES256 => {
            verify_ring(&signature::ECDSA_P256_SHA256_FIXED, signature, signing_input, public_key)
        }
        Algorithm::ES384 => {
            verify_ring(&signature::ECDSA_P384_SHA384_FIXED, signature, signing_input, public_key)
        }
        Algorithm::RS256 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signature,
            signing_input,
            public_key,
        ),
        Algorithm::RS384 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            signature,
            signing_input,
            public_key,
        ),
        Algorithm::RS512 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            signature,
            signing_input,
            public_key,
        ),
    }
}

/// The supported RSA key formats, see the documentation for ring::signature::RsaKeyPair
/// for more information
pub enum KeyFormat {
    /// An unencrypted PKCS#8-encoded key. Can be used with both ECDSA and RSA
    /// algorithms when signing. See ring for information.
    PKCS8,
    /// A binary DER-encoded ASN.1 key. Can only be used with RSA algorithms
    /// when signing. See ring for more information
    DER,
    /// This is not a key format, but provided for convenience since HMAC is
    /// a supported signing algorithm.
    HMAC,
}

/// A tiny abstraction on top of raw key buffers to add key format
/// information
pub trait Key: AsRef<[u8]> {
    /// The format of the key
    fn format(&self) -> KeyFormat;
}

/// This blanket implementation aligns with the key loading as of version 6.0.0
// impl<T> Key for T
// where
//     T: AsRef<[u8]>,
// {
//     fn format(&self) -> KeyFormat {
//         KeyFormat::DER
//     }
// }

/// A convenience wrapper for a key buffer as an unencrypted PKCS#8-encoded,
/// see ring for more details
pub struct Pkcs8<'a> {
    key_bytes: &'a [u8],
}

impl<'a> Key for Pkcs8<'a> {
    fn format(&self) -> KeyFormat {
        KeyFormat::PKCS8
    }
}

impl<'a> AsRef<[u8]> for Pkcs8<'a> {
    fn as_ref(&self) -> &[u8] {
        self.key_bytes
    }
}

impl<'a, T> From<&'a T> for Pkcs8<'a>
where
    T: AsRef<[u8]>,
{
    fn from(key: &'a T) -> Self {
        Self { key_bytes: key.as_ref() }
    }
}

/// A convenience wrapper for a key buffer as a binary DER-encoded ASN.1 key,
/// see ring for more details
pub struct Der<'a> {
    key_bytes: &'a [u8],
}

impl<'a> Key for Der<'a> {
    fn format(&self) -> KeyFormat {
        KeyFormat::DER
    }
}

impl<'a> AsRef<[u8]> for Der<'a> {
    fn as_ref(&self) -> &[u8] {
        self.key_bytes
    }
}

impl<'a, T> From<&'a T> for Der<'a>
where
    T: AsRef<[u8]>,
{
    fn from(key: &'a T) -> Self {
        Self { key_bytes: key.as_ref() }
    }
}

/// Convenience wrapper for an HMAC key
pub struct Hmac<'a> {
    key_bytes: &'a [u8],
}

impl<'a> Key for Hmac<'a> {
    fn format(&self) -> KeyFormat {
        KeyFormat::HMAC
    }
}

impl<'a> AsRef<[u8]> for Hmac<'a> {
    fn as_ref(&self) -> &[u8] {
        self.key_bytes
    }
}

impl<'a, T> From<&'a T> for Hmac<'a>
where
    T: AsRef<[u8]>,
{
    fn from(key: &'a T) -> Self {
        Self { key_bytes: key.as_ref() }
    }
}

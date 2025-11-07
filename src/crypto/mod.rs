//! The cryptography of the `jsonwebtoken` crate is decoupled behind
//! [`JwtSigner`] and [`JwtVerifier`] traits. These make use of `signature`'s
//! [`Signer`] and [`Verifier`] traits respectively.
//! Crypto provider selection is handled by [`CryptoProvider`].
//!
//! [`JwtSigner`]: crate::crypto::JwtSigner
//! [`JwtVerifier`]: crate::crypto::JwtVerifier
//! [`Signer`]: signature::Signer
//! [`Verifier`]: signature::Verifier
//! [`CryptoProvider`]: crate::crypto::CryptoProvider

use std::sync::Arc;

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::jwk::{EllipticCurve, ThumbprintHash};
use crate::{DecodingKey, EncodingKey};

#[macro_use]
mod macros;

/// `aws_lc_rs` based CryptoProvider.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc;

/// `RustCrypto` based CryptoProvider.
#[cfg(feature = "rust_crypto")]
pub mod rust_crypto;

use crate::serialization::{b64_decode, b64_encode};
use signature::{Signer, Verifier};

/// Trait providing the functionality to sign a JWT.
///
/// Allows an arbitrary crypto backend to be provided.
pub trait JwtSigner: Signer<Vec<u8>> {
    /// Return the [`Algorithm`] corresponding to the signing module.
    fn algorithm(&self) -> Algorithm;
}

/// Trait providing the functionality to verify a JWT.
///
/// Allows an arbitrary crypto backend to be provided.
pub trait JwtVerifier: Verifier<Vec<u8>> {
    /// Return the [`Algorithm`] corresponding to the signing module.
    fn algorithm(&self) -> Algorithm;
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    let provider = (CryptoProvider::get_default_or_install_from_crate_features().signer_factory)(
        &algorithm, key,
    )?;
    Ok(b64_encode(provider.sign(message)))
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    let provider = (CryptoProvider::get_default_or_install_from_crate_features().verifier_factory)(
        &algorithm, key,
    )?;
    Ok(provider.verify(message, &b64_decode(signature)?).is_ok())
}

/// Controls the cryptography used be jsonwebtoken.
///
/// You can either install one of the built-in options:
/// - [`crypto::aws_lc::DEFAULT_PROVIDER`]: (behind the `aws-lc` crate feature).
///   This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs) crate.
/// - [`crypto::rust_crypto::DEFAULT_PROVIDER`]: (behind the `rust_crypto` crate feature)
///   This provider uses crates from the [Rust Crypto](https://github.com/RustCrypto) project.
///
/// or provide your own custom custom implementation of `CryptoProvider`
/// (see the `custom_provider` example).
// This implementation appropriates a good chunk of code from the `rustls` CryptoProvider,
// and is very much inspired by it.
#[derive(Clone, Debug)]
pub struct CryptoProvider {
    /// A function that produces a [`JwtSigner`] for a given [`Algorithm`]
    pub signer_factory: fn(&Algorithm, &EncodingKey) -> Result<Box<dyn JwtSigner>>,
    /// A function that produces a [`JwtVerifier`] for a given [`Algorithm`]
    pub verifier_factory: fn(&Algorithm, &DecodingKey) -> Result<Box<dyn JwtVerifier>>,
    /// Struct with utility functions for JWK processing.
    pub jwk_utils: JwkUtils,
}

impl CryptoProvider {
    /// Set this `CryptoProvider` as the default for this process.
    ///
    /// This can be called successfully at most once in any process execution.
    pub fn install_default(self) -> std::result::Result<(), Arc<Self>> {
        static_default::install_default(self)
    }

    /// Get the default `CryptoProvider` for this process.
    ///
    /// This will be `None` if no default has been set yet.
    pub fn get_default() -> Option<&'static Arc<Self>> {
        static_default::get_default()
    }

    /// Get the default if it has been set yet, or determine one from the crate features if possible.
    pub(crate) fn get_default_or_install_from_crate_features() -> &'static Arc<Self> {
        if let Some(provider) = Self::get_default() {
            return provider;
        }

        let provider = Self::from_crate_features()
            .expect(r###"
Could not automatically determine the process-level CryptoProvider from jsonwebtoken crate features.
Call CryptoProvider::install_default() before this point to select a provider manually, or make sure exactly one of the 'rust_crypto' and 'aws_lc_rs' features is enabled.
See the documentation of the CryptoProvider type for more information.
            "###);
        let _ = provider.install_default();
        Self::get_default().unwrap()
    }

    /// Determine a `CryptoProvider` based on crate features.
    pub fn from_crate_features() -> Option<Self> {
        #[cfg(all(
            feature = "rust_crypto",
            not(feature = "aws_lc_rs"),
            not(feature = "custom-provider")
        ))]
        {
            return Some(rust_crypto::DEFAULT_PROVIDER);
        }

        #[cfg(all(
            feature = "aws_lc_rs",
            not(feature = "rust_crypto"),
            not(feature = "custom-provider")
        ))]
        {
            return Some(aws_lc::DEFAULT_PROVIDER);
        }

        #[allow(unreachable_code)]
        None
    }
}

/// Holds utility functions needed for JWK processing.
/// The `Default` implementation initializes all functions to `unimplemented!()`.
#[derive(Clone, Debug)]
pub struct JwkUtils {
    /// Given a DER encoded private key, extract the RSA public key components (n, e)
    #[allow(clippy::type_complexity)]
    pub extract_rsa_public_key_components: fn(&[u8]) -> Result<(Vec<u8>, Vec<u8>)>,
    /// Given a DER encoded private key and an algorithm, extract the associated curve
    /// and the EC public key components (x, y)
    #[allow(clippy::type_complexity)]
    pub extract_ec_public_key_coordinates:
        fn(&[u8], Algorithm) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)>,
    /// Given some data and a name of a hash function, compute hash_function(data)
    pub compute_digest: fn(&[u8], ThumbprintHash) -> Vec<u8>,
}

impl Default for JwkUtils {
    fn default() -> Self {
        Self {
            extract_rsa_public_key_components: |_| unimplemented!(),
            extract_ec_public_key_coordinates: |_, _| unimplemented!(),
            compute_digest: |_, _| unimplemented!(),
        }
    }
}

mod static_default {
    use std::sync::{Arc, OnceLock};

    use super::CryptoProvider;

    static PROCESS_DEFAULT_PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

    pub(crate) fn install_default(
        default_provider: CryptoProvider,
    ) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.set(Arc::new(default_provider))
    }

    pub(crate) fn get_default() -> Option<&'static Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.get()
    }
}

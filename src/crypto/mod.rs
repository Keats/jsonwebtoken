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

use crate::algorithms::Algorithm;
use crate::errors::{ErrorKind, Result, new_error};
use crate::jwk::{EllipticCurve, ThumbprintHash};
use crate::{DecodingKey, EncodingKey};

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
    let provider = (CryptoProvider::get_default().signer_factory)(&algorithm, key)?;
    Ok(b64_encode(provider.try_sign(message)?))
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
    let provider = (CryptoProvider::get_default().verifier_factory)(&algorithm, key)?;
    Ok(provider.verify(message, &b64_decode(signature)?).is_ok())
}

/// Controls the cryptography used by jsonwebtoken.
///
/// You can either install one of the built-in options:
/// - [`crypto::aws_lc::DEFAULT_PROVIDER`]: (behind the `aws_lc_rs` crate feature).
///   This provider uses the [aws-lc-rs](https://github.com/aws/aws-lc-rs) crate.
/// - [`crypto::rust_crypto::DEFAULT_PROVIDER`]: (behind the `rust_crypto` crate feature)
///   This provider uses crates from the [Rust Crypto](https://github.com/RustCrypto) project.
///
/// or provide your own custom custom implementation of `CryptoProvider`.
// This implementation appropriates a good chunk of code from the `rustls` CryptoProvider,
// and is very much inspired by it.
#[derive(Clone, Debug)]
pub struct CryptoProvider {
    /// A function that produces a [`JwtSigner`] for a given [`Algorithm`]
    pub signer_factory: fn(&Algorithm, &EncodingKey) -> Result<Box<dyn JwtSigner>>,
    /// A function that produces a [`JwtVerifier`] for a given [`Algorithm`]
    pub verifier_factory: fn(&Algorithm, &DecodingKey) -> Result<Box<dyn JwtVerifier>>,
    /// Struct with utility functions for JWK processing.
    pub key_utils: KeyUtils,
}

impl CryptoProvider {
    /// Set this `CryptoProvider` as the default for this process.
    ///
    /// This can be called successfully at most once in any process execution.
    pub fn install_default(&'static self) -> std::result::Result<(), &'static Self> {
        static_default::install_default(self)
    }

    /// Returns the process-level [`CryptoProvider`], if one is available, without panicking.
    ///
    /// This is `Some` if [`CryptoProvider::install_default`] has been called, or if
    /// exactly one of the `aws_lc_rs` and `rust_crypto` features is enabled. It is
    /// `None` if both features or neither are enabled and nothing has been installed.
    ///
    /// Call this at startup to fail on a misconfigured build at a point of your
    /// choosing, rather than on the first `encode`/`decode`.
    pub fn try_get_default() -> Option<&'static Self> {
        static_default::try_get_default()
    }

    pub(crate) fn get_default() -> &'static Self {
        static_default::get_default()
    }

    fn from_crate_features() -> Option<&'static Self> {
        #[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
        {
            return Some(&rust_crypto::DEFAULT_PROVIDER);
        }

        #[cfg(all(feature = "aws_lc_rs", not(feature = "rust_crypto")))]
        {
            return Some(&aws_lc::DEFAULT_PROVIDER);
        }

        #[allow(unreachable_code)]
        None
    }
}

/// Holds utility functions required for JWK processing.
/// Use the [`KeyUtils::new_unimplemented`] function if your provider does not support JWKs.
#[derive(Clone, Debug)]
pub struct KeyUtils {
    /// Given a DER encoded private key, extract the RSA public key components (n, e)
    #[allow(clippy::type_complexity)]
    pub rsa_pub_components_from_private_key: fn(&[u8]) -> Result<(Vec<u8>, Vec<u8>)>,
    /// Given a DER encoded public key, extract the RSA public key components (n, e)
    #[allow(clippy::type_complexity)]
    pub rsa_pub_components_from_public_key: fn(&[u8]) -> Result<(Vec<u8>, Vec<u8>)>,
    /// Given a DER encoded private key and an algorithm, extract the associated curve
    /// and the EC public key components (x, y)
    #[allow(clippy::type_complexity)]
    pub ec_pub_components_from_private_key:
        fn(&[u8], Algorithm) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)>,
    /// Given a DER encoded private key and the curve type, extract the ED public key component (x)
    pub ed_pub_components_from_private_key: fn(&[u8], &EllipticCurve) -> Result<Vec<u8>>,
    /// Given some data and a name of a hash function, compute hash_function(data)
    pub compute_digest: fn(&[u8], ThumbprintHash) -> Result<Vec<u8>>,
}

impl KeyUtils {
    /// Initialises all values to stubs that return
    /// [`ErrorKind::Provider`](crate::errors::ErrorKind::Provider).
    ///
    /// Use this if your [`CryptoProvider`] does not support JWKs. Whether a caller
    /// reaches one of these stubs depends on the key they pass at runtime, so this
    /// is reported through the `Result` these functions already return rather than
    /// by panicking.
    pub const fn new_unimplemented() -> Self {
        const UNIMPLEMENTED: &str = "this CryptoProvider does not implement JWKs";

        Self {
            rsa_pub_components_from_private_key: |_| {
                Err(new_error(ErrorKind::Provider(UNIMPLEMENTED.to_string())))
            },
            rsa_pub_components_from_public_key: |_| {
                Err(new_error(ErrorKind::Provider(UNIMPLEMENTED.to_string())))
            },
            ec_pub_components_from_private_key: |_, _| {
                Err(new_error(ErrorKind::Provider(UNIMPLEMENTED.to_string())))
            },
            ed_pub_components_from_private_key: |_, _| {
                Err(new_error(ErrorKind::Provider(UNIMPLEMENTED.to_string())))
            },
            compute_digest: |_, _| Err(new_error(ErrorKind::Provider(UNIMPLEMENTED.to_string()))),
        }
    }
}

/// Given bitstring from DER encoded public key, extract the associated curve
/// and the EC public key components (x, y)
pub(crate) fn ec_pub_components_from_public_key(
    pub_bytes: &[u8],
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let (curve, pub_elem_bytes) = match pub_bytes.len() {
        65 => (EllipticCurve::P256, 32),
        97 => (EllipticCurve::P384, 48),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };

    if pub_bytes[0] != 4 {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }

    let (x, y) = pub_bytes[1..].split_at(pub_elem_bytes);
    Ok((curve, x.to_vec(), y.to_vec()))
}

mod static_default {
    use std::sync::OnceLock;

    use super::CryptoProvider;

    static PROCESS_DEFAULT_PROVIDER: OnceLock<&'static CryptoProvider> = OnceLock::new();

    pub(crate) fn install_default(
        default_provider: &'static CryptoProvider,
    ) -> Result<(), &'static CryptoProvider> {
        PROCESS_DEFAULT_PROVIDER.set(default_provider)
    }

    pub(crate) fn try_get_default() -> Option<&'static CryptoProvider> {
        if let Some(provider) = PROCESS_DEFAULT_PROVIDER.get() {
            return Some(provider);
        }
        // Only ever store a real provider. Storing a placeholder here would consume the
        // `OnceLock` and make a later `install_default` fail forever, even if the caller
        // recovers from the panic below.
        CryptoProvider::from_crate_features()
            .map(|provider| *PROCESS_DEFAULT_PROVIDER.get_or_init(|| provider))
    }

    pub(crate) fn get_default() -> &'static CryptoProvider {
        match try_get_default() {
            Some(provider) => provider,
            None => panic!("{}", NOT_INSTALLED_ERROR),
        }
    }

    #[cfg(all(feature = "aws_lc_rs", feature = "rust_crypto"))]
    const NOT_INSTALLED_ERROR: &str = r"
Could not automatically determine the process-level CryptoProvider from jsonwebtoken crate features:
both the 'aws_lc_rs' and 'rust_crypto' features are enabled, so the choice is ambiguous.
Enable exactly one of them, or call CryptoProvider::install_default() before this point.
Note that Cargo unifies features, so another dependency may have enabled the second backend.
See the documentation of the CryptoProvider type for more information.
";

    #[cfg(not(all(feature = "aws_lc_rs", feature = "rust_crypto")))]
    const NOT_INSTALLED_ERROR: &str = r"
Could not automatically determine the process-level CryptoProvider from jsonwebtoken crate features:
neither the 'aws_lc_rs' nor the 'rust_crypto' feature is enabled.
Enable exactly one of them, or call CryptoProvider::install_default() before this point.
See the documentation of the CryptoProvider type for more information.
";
}

//! The cryptography of the `jsonwebtoken` crate is decoupled behind
//! [`JwtSigner`] and [`JwtVerifier`] traits. These make use of `RustCrypto`'s
//! [`Signer`] and [`Verifier`] traits respectively.

use crate::algorithms::Algorithm;

#[cfg(feature = "aws_lc_rs")]
pub(crate) mod aws_lc;
#[cfg(feature = "rust_crypto")]
pub(crate) mod rust_crypto;

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

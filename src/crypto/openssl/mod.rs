//! OpenSSL crypto backend for JWT operations.
//!
//! This backend uses the OpenSSL library for cryptographic operations.
//! It's useful when:
//! - You need FIPS 140-2 compliance (with OpenSSL FIPS module)
//! - OpenSSL is already a dependency in your project
//! - You need to use system-provided crypto libraries
//! - You're working in an environment where OpenSSL is preferred or mandated
//!
//! To use this backend, enable the `openssl_crypto` feature in your `Cargo.toml`:
//!
//! ```toml
//! jsonwebtoken = { version = "10", features = ["openssl_crypto"] }
//! ```
//!
//! Note: Only one crypto backend can be enabled at a time.

pub(crate) mod ecdsa;
pub(crate) mod eddsa;
pub(crate) mod hmac;
pub(crate) mod rsa;

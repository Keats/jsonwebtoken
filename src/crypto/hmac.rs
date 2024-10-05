//! Common HMAC related functionality.

use std::ops::Deref;

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::errors::Result;

/// The shared secret used for the HMAC family of algorithms.
#[derive(Debug)]
pub struct HmacSecret(Vec<u8>);

impl HmacSecret {
    /// If you're using an HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        Self(secret.to_vec())
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        Ok(Self(STANDARD.decode(secret)?))
    }
}

impl Deref for HmacSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

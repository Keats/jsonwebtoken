//! # Todo
//!
//! - Documentation

use serde::Serialize;

use crate::{
    crypto::{
        hmac::{HmacSecret, Hs256, Hs384},
        JwtSigner,
    },
    errors::{new_error, Result},
    serialization::{b64_encode, b64_encode_part},
    Header,
};

/// # Todo
///
/// - Documentation
pub struct JwtEncoder {
    signing_provider: Box<dyn JwtSigner>,
    header: Header,
}

impl JwtEncoder {
    /// Todo
    pub fn from_signer<S: JwtSigner + 'static>(signing_provider: S) -> Self {
        Self::from_boxed_signer(Box::new(signing_provider))
    }

    /// Create a new [`JwtEncoder`] with any crypto provider that implements the [`CryptoProvider`] trait.
    pub fn from_boxed_signer(signing_provider: Box<dyn JwtSigner>) -> Self {
        // Determine a default header
        let mut header = Header::new(signing_provider.algorithm());
        header.typ = Some("JWT".to_owned());

        Self { signing_provider, header }
    }

    /// Provide a custom header.
    ///
    /// This would be used in the rare cases that fields other than `algorithm` and `type` need to be populated.
    ///
    /// # Todo
    ///
    /// - Test the the error checking works
    pub fn with_header(mut self, header: Header) -> Result<Self> {
        // Check that the header makes use of the correct algorithm
        if header.alg != self.signing_provider.algorithm() {
            return Err(new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }

        self.header = header;
        Ok(self)
    }

    /// Encode and sign the `claims` as a JWT.
    ///
    /// # Todo
    ///
    /// - Put in example usage.
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        let encoded_header = b64_encode_part(&self.header)?;
        let encoded_claims = b64_encode_part(claims)?;
        let message = [encoded_header, encoded_claims].join(".");

        let signature = b64_encode(&self.signing_provider.sign(message.as_bytes()));

        Ok([message, signature].join("."))
    }

    /// Create new [`JwtEncoder`] with the `HS256` algorithm.
    pub fn hs_256(secret: HmacSecret) -> Result<JwtEncoder> {
        let signing_provider = Box::new(Hs256::new(secret)?);

        Ok(JwtEncoder::from_boxed_signer(signing_provider))
    }

    /// Create new [`JwtEncoder`] with the `HS384` algorithm.
    pub fn hs_384(secret: HmacSecret) -> Result<JwtEncoder> {
        let signing_provider = Box::new(Hs384::new(secret)?);

        Ok(JwtEncoder::from_boxed_signer(signing_provider))
    }
}

#[cfg(test)]
mod builder_tests {

    use super::*;

    #[derive(Debug, Serialize)]
    struct Claims {
        sub: String,
        age: u32,
    }

    #[test]
    fn test_builder() {
        // Arrange
        let claims = Claims { sub: "123345".to_owned(), age: 25 };
        let secret = HmacSecret::from_secret("test".as_ref());

        // Act
        let jwt = JwtEncoder::hs_256(secret).unwrap().encode(&claims).unwrap();

        dbg!(&jwt);

        // Assert
    }
}

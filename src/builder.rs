//! # Todo
//!
//! - Documentation

use serde::Serialize;

use crate::{
    crypto::JwtSigner,
    errors::{new_error, Result},
    serialization::{b64_encode, b64_encode_part},
    Header,
};

/// # Todo
///
/// - Documentation
pub struct JwtEncoder<C: JwtSigner> {
    signing_provider: C,
    header: Header,
}

impl<C: JwtSigner> JwtEncoder<C> {
    /// Create a new [`JwtEncoder`] with any crypto provider that implements the [`CryptoProvider`] trait.
    pub fn new(signing_provider: C) -> Self {
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
}

#[cfg(test)]
mod builder_tests {
    use crate::crypto::hmac::HmacSha256Trait;

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
        let signer = HmacSha256Trait::new("k3XTGsWiuO0stzhwPkuF2R6FdFY2crfyAVDjSBX34bW41ektItjp340PNXz1UvLkaq4CcT6ZMl7GXzfTvCvpkFXJbMni1wj40g423FbUxI7ZclVyzIrVFywrB5trt94Rv9AkTpShXzpnEWKGhZdD0MIOrQlg".as_ref()).unwrap();

        // Act
        let jwt = JwtEncoder::new(signer).encode(&claims).unwrap();

        dbg!(&jwt);

        // Assert
    }
}

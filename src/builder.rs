//! # Todo
//!
//! - Documentation

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::{
        hmac::{HmacSecret, Hs256, Hs384},
        JwtSigner, JwtVerifier,
    },
    errors::{new_error, ErrorKind, Result},
    serialization::{b64_encode, b64_encode_part, DecodedJwtPartClaims},
    validation::validate,
    Header, TokenData, Validation,
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
    pub fn with_header(mut self, header: &Header) -> Result<Self> {
        // Check that the header makes use of the correct algorithm
        if header.alg != self.signing_provider.algorithm() {
            return Err(new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }

        self.header = header.clone();
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

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

/// Todo
pub struct JwtDecoder {
    verifying_provider: Box<dyn JwtVerifier>,
    validation: Validation,
}

impl JwtDecoder {
    /// Todo
    pub fn from_verifier<V: JwtVerifier + 'static>(verifying_provider: V) -> Self {
        Self::from_boxed_verifiyer(Box::new(verifying_provider))
    }

    /// Todo
    pub fn from_boxed_verifiyer(verifying_provider: Box<dyn JwtVerifier>) -> Self {
        let validation = Validation::new(verifying_provider.algorithm());

        Self { verifying_provider, validation }
    }

    /// Todo
    pub fn with_validation(mut self, validation: &Validation) -> Result<Self> {
        // Check that the validation contains the correct algorithm
        if !validation.algorithms.contains(&self.verifying_provider.algorithm()) {
            return Err(new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }

        self.validation = validation.clone();
        Ok(self)
    }

    /// Todo
    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<TokenData<T>> {
        let (header, claims) = self.verify_signature(token)?;

        let decoded_claims = DecodedJwtPartClaims::from_jwt_part_claims(claims)?;
        let claims = decoded_claims.deserialize()?;
        validate(decoded_claims.deserialize()?, &self.validation)?;

        Ok(TokenData { header, claims })
    }

    /// Verify signature of a JWT, and return header object and raw payload
    ///
    /// If the token or its signature is invalid, it will return an error.
    fn verify_signature<'a>(&self, token: &'a str) -> Result<(Header, &'a str)> {
        if self.validation.validate_signature && self.validation.algorithms.is_empty() {
            return Err(new_error(ErrorKind::MissingAlgorithm));
        }

        // Todo: This behaviour is currently not captured anywhere.
        // if validation.validate_signature {
        //     for alg in &validation.algorithms {
        //         if key.family != alg.family() {
        //             return Err(new_error(ErrorKind::InvalidAlgorithm));
        //         }
        //     }
        // }

        let (signature, message) = expect_two!(token.rsplitn(2, '.'));
        let (payload, header) = expect_two!(message.rsplitn(2, '.'));
        let header = Header::from_encoded(header)?;

        if self.validation.validate_signature && !self.validation.algorithms.contains(&header.alg) {
            return Err(new_error(ErrorKind::InvalidAlgorithm));
        }

        if self.validation.validate_signature
            && self
                .verifying_provider
                .verify(message.as_bytes(), &signature.as_bytes().to_vec())
                .is_err()
        {
            return Err(new_error(ErrorKind::InvalidSignature));
        }

        Ok((header, payload))
    }

    /// Create new [`JwtDecoder`] with the `HS256` algorithm.
    pub fn hs_256(secret: HmacSecret) -> Result<JwtDecoder> {
        let verifying_provider = Box::new(Hs256::new(secret)?);

        Ok(JwtDecoder::from_boxed_verifiyer(verifying_provider))
    }

    /// Create new [`JwtDecoder`] with the `HS384` algorithm.
    pub fn hs_384(secret: HmacSecret) -> Result<JwtDecoder> {
        let verifying_provider = Box::new(Hs384::new(secret)?);

        Ok(JwtDecoder::from_boxed_verifiyer(verifying_provider))
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

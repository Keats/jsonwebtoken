use crate::{decode, errors::*, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

/// `Validator` is a bridge struct between `DecodingKey` and `Validation` which simplifies validating tokens
#[derive(Debug, Clone, PartialEq)]
pub struct Validator {
    decoding_key: DecodingKey,
    validation: Validation,
}
impl Validator {
    /// Creating new `Validator`
    pub fn new(decoding_key: DecodingKey, validation: Validation) -> Self {
        Self { decoding_key, validation }
    }

    /// Set new validation
    pub fn set_validation(&mut self, validation: Validation) {
        self.validation = validation;
    }

    /// Set new DecodingKey
    pub fn set_decoding_key(&mut self, decoding_key: DecodingKey) {
        self.decoding_key = decoding_key;
    }

    /// Validate given token and returns TokenData on success
    pub fn validate<T: DeserializeOwned>(&self, token: &str) -> Result<TokenData<T>> {
        decode::<T>(&token, &self.decoding_key, &self.validation)
    }
}

impl From<DecodingKey> for Validator {
    fn from(decoding_key: DecodingKey) -> Self {
        Self { decoding_key, validation: Validation::default() }
    }
}

impl From<&DecodingKey> for Validator {
    fn from(decoding_key: &DecodingKey) -> Self {
        Self { decoding_key: decoding_key.clone(), validation: Validation::default() }
    }
}

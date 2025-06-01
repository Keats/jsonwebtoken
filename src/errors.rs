use std::error::Error as StdError;
use std::fmt;
use std::result;
use std::sync::Arc;

/// A crate private constructor for `Error`.
pub(crate) fn new_error(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

/// A type alias for `Result<T, jsonwebtoken::errors::Error>`.
pub type Result<T> = result::Result<T, Error>;

/// An error that can occur when encoding/decoding JWTs
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(Box<ErrorKind>);

impl Error {
    /// Return the specific type of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    /// Unwrap this error into its underlying type.
    pub fn into_kind(self) -> ErrorKind {
        *self.0
    }
}

/// The specific type of an error.
///
/// This enum may grow additional variants, the `#[non_exhaustive]`
/// attribute makes sure clients don't count on exhaustive matching.
/// (Otherwise, adding a new variant could break existing code.)
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum ErrorKind {
    /// Errors related to malformed tokens or cryptographic key problems.
    Fundamental(FundamentalError),
    /// Errors that occur when a token fails claim-based validation.
    Validation(ValidationError),
    /// Errors originating from third-party libraries used for tasks like
    /// base64 decoding, JSON serialization, or cryptographic operations.
    ThirdParty(ThirdPartyError),
}

impl From<FundamentalError> for ErrorKind {
    fn from(value: FundamentalError) -> Self {
        Self::Fundamental(value)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug)]
/// Errors that indicate a fundamental issue with the JWT or cryptographic key configuration.
/// This enum may grow additional variants, the `#[non_exhaustive]`
/// attribute makes sure clients don't count on exhaustive matching.
/// (Otherwise, adding a new variant could break existing code.)
pub enum FundamentalError {
    /// When a token doesn't have a valid JWT shape
    InvalidToken,
    /// When the signature doesn't match
    InvalidSignature,
    /// When the secret given is not a valid ECDSA key
    InvalidEcdsaKey,
    /// When the secret given is not a valid RSA key
    InvalidRsaKey(String),
    /// We could not sign with the given key
    RsaFailedSigning,
    /// When the algorithm from string doesn't match the one passed to `from_str`
    InvalidAlgorithmName,
    /// When a key is provided with an invalid format
    InvalidKeyFormat,
}

impl From<ValidationError> for ErrorKind {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug)]
/// Errors which relate to the validation of a JWT's claims (such as expiration, audience, or issuer)
/// and whether they meet the defined criteria.
pub enum ValidationError {
    // Validation errors
    /// When a claim required by the validation is not present
    MissingRequiredClaim(String),
    /// When a token’s `exp` claim indicates that it has expired
    ExpiredSignature,
    /// When a token’s `iss` claim does not match the expected issuer
    InvalidIssuer,
    /// When a token’s `aud` claim does not match one of the expected audience values
    InvalidAudience,
    /// When a token’s `sub` claim does not match one of the expected subject values
    InvalidSubject,
    /// When a token’s `nbf` claim represents a time in the future
    ImmatureSignature,
    /// When the algorithm in the header doesn't match the one passed to `decode` or the encoding/decoding key
    /// used doesn't match the alg requested
    InvalidAlgorithm,
    /// When the Validation struct does not contain at least 1 algorithm
    MissingAlgorithm,
}

impl From<ThirdPartyError> for ErrorKind {
    fn from(value: ThirdPartyError) -> Self {
        Self::ThirdParty(value)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug)]
/// Errors originating from external libraries/underlying systems
/// used during the JWT encoding or decoding process.
pub enum ThirdPartyError {
    // 3rd party errors
    /// An error happened when decoding some base64 text
    Base64(base64::DecodeError),
    /// An error happened while serializing/deserializing JSON
    Json(Arc<serde_json::Error>),
    /// Some of the text was invalid UTF-8
    Utf8(::std::string::FromUtf8Error),
    /// Something unspecified went wrong with crypto
    Crypto(::ring::error::Unspecified),
}

impl StdError for Error {
    fn cause(&self) -> Option<&dyn StdError> {
        match &*self.0 {
            ErrorKind::Fundamental(_) => None,
            ErrorKind::Validation(_) => None,
            ErrorKind::ThirdParty(ThirdPartyError::Base64(err)) => Some(err),
            ErrorKind::ThirdParty(ThirdPartyError::Json(err)) => Some(err.as_ref()),
            ErrorKind::ThirdParty(ThirdPartyError::Utf8(err)) => Some(err),
            ErrorKind::ThirdParty(ThirdPartyError::Crypto(err)) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self.0 {
            ErrorKind::Fundamental(FundamentalError::InvalidRsaKey(msg)) => {
                write!(f, "RSA key invalid: {}", msg)
            }
            ErrorKind::Validation(ValidationError::MissingRequiredClaim(claim)) => {
                write!(f, "Missing required claim: {}", claim)
            }
            ErrorKind::ThirdParty(ThirdPartyError::Json(err)) => {
                write!(f, "JSON error: {}", err)
            }
            ErrorKind::ThirdParty(ThirdPartyError::Utf8(err)) => {
                write!(f, "UTF-8 error: {}", err)
            }
            ErrorKind::ThirdParty(ThirdPartyError::Crypto(err)) => {
                write!(f, "Crypto error: {}", err)
            }
            ErrorKind::ThirdParty(ThirdPartyError::Base64(err)) => {
                write!(f, "Base64 error: {}", err)
            }
            _ => write!(f, "{:?}", self.0),
        }
    }
}

impl PartialEq for ErrorKind {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

// Equality of ErrorKind is an equivalence relation: it is reflexive, symmetric and transitive.
impl Eq for ErrorKind {}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        new_error(ErrorKind::ThirdParty(ThirdPartyError::Base64(err)))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        new_error(ErrorKind::ThirdParty(ThirdPartyError::Json(Arc::new(err))))
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(err: ::std::string::FromUtf8Error) -> Error {
        new_error(ErrorKind::ThirdParty(ThirdPartyError::Utf8(err)))
    }
}

impl From<::ring::error::Unspecified> for Error {
    fn from(err: ::ring::error::Unspecified) -> Error {
        new_error(ErrorKind::ThirdParty(ThirdPartyError::Crypto(err)))
    }
}

impl From<::ring::error::KeyRejected> for Error {
    fn from(_err: ::ring::error::KeyRejected) -> Error {
        new_error(ErrorKind::Fundamental(FundamentalError::InvalidEcdsaKey))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        new_error(kind)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[test]
    #[wasm_bindgen_test]
    fn test_error_rendering() {
        assert_eq!(
            "InvalidAlgorithmName",
            Error::from(ErrorKind::Fundamental(FundamentalError::InvalidAlgorithmName)).to_string()
        );
    }
}

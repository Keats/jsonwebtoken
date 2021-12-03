use std::error::Error as StdError;
use std::fmt;
use std::result;
use std::sync::Arc;

/// A crate private constructor for `Error`.
pub(crate) fn new_error(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

/// A type alias for `Result<T, jsonwebtoken::Error>`.
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
    /// When a token doesn't have a valid JWT shape
    InvalidToken,
    /// When the signature doesn't match
    InvalidSignature,
    /// When the secret given is not a valid ECDSA key
    InvalidEcdsaKey,
    /// When the secret given is not a valid RSA key
    InvalidRsaKey(&'static str),
    /// We could not sign with the given key
    RsaFailedSigning,
    /// When the algorithm from string doesn't match the one passed to `from_str`
    InvalidAlgorithmName,
    /// When a key is provided with an invalid format
    InvalidKeyFormat,

    // Validation errors
    /// When a claim required by the validation is not present
    MissingRequiredClaim(String),
    /// When a token’s `exp` claim indicates that it has expired
    ExpiredSignature,
    /// When a token’s `iss` claim does not match the expected issuer
    InvalidIssuer,
    /// When a token’s `aud` claim does not match one of the expected audience values
    InvalidAudience,
    /// When a token’s `sub` claim does not match one of the expected audience values
    InvalidSubject,
    /// When a token’s nbf claim represents a time in the future
    ImmatureSignature,
    /// When the algorithm in the header doesn't match the one passed to `decode` or the encoding/decoding key
    /// used doesn't match the alg requested
    InvalidAlgorithm,
    /// When the Validation struct does not contain at least 1 algorithm
    MissingAlgorithm,

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
        match *self.0 {
            ErrorKind::InvalidToken => None,
            ErrorKind::InvalidSignature => None,
            ErrorKind::InvalidEcdsaKey => None,
            ErrorKind::RsaFailedSigning => None,
            ErrorKind::InvalidRsaKey(_) => None,
            ErrorKind::ExpiredSignature => None,
            ErrorKind::MissingAlgorithm => None,
            ErrorKind::MissingRequiredClaim(_) => None,
            ErrorKind::InvalidIssuer => None,
            ErrorKind::InvalidAudience => None,
            ErrorKind::InvalidSubject => None,
            ErrorKind::ImmatureSignature => None,
            ErrorKind::InvalidAlgorithm => None,
            ErrorKind::InvalidAlgorithmName => None,
            ErrorKind::InvalidKeyFormat => None,
            ErrorKind::Base64(ref err) => Some(err),
            ErrorKind::Json(ref err) => Some(err.as_ref()),
            ErrorKind::Utf8(ref err) => Some(err),
            ErrorKind::Crypto(ref err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::InvalidToken
            | ErrorKind::InvalidSignature
            | ErrorKind::InvalidEcdsaKey
            | ErrorKind::ExpiredSignature
            | ErrorKind::RsaFailedSigning
            | ErrorKind::MissingAlgorithm
            | ErrorKind::InvalidIssuer
            | ErrorKind::InvalidAudience
            | ErrorKind::InvalidSubject
            | ErrorKind::ImmatureSignature
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::InvalidKeyFormat
            | ErrorKind::InvalidAlgorithmName => write!(f, "{:?}", self.0),
            ErrorKind::MissingRequiredClaim(ref c) => write!(f, "Missing required claim: {}", c),
            ErrorKind::InvalidRsaKey(ref msg) => write!(f, "RSA key invalid: {}", msg),
            ErrorKind::Json(ref err) => write!(f, "JSON error: {}", err),
            ErrorKind::Utf8(ref err) => write!(f, "UTF-8 error: {}", err),
            ErrorKind::Crypto(ref err) => write!(f, "Crypto error: {}", err),
            ErrorKind::Base64(ref err) => write!(f, "Base64 error: {}", err),
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
        new_error(ErrorKind::Base64(err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        new_error(ErrorKind::Json(Arc::new(err)))
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(err: ::std::string::FromUtf8Error) -> Error {
        new_error(ErrorKind::Utf8(err))
    }
}

impl From<::ring::error::Unspecified> for Error {
    fn from(err: ::ring::error::Unspecified) -> Error {
        new_error(ErrorKind::Crypto(err))
    }
}

impl From<::ring::error::KeyRejected> for Error {
    fn from(_err: ::ring::error::KeyRejected) -> Error {
        new_error(ErrorKind::InvalidEcdsaKey)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        new_error(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_rendering() {
        assert_eq!(
            "InvalidAlgorithmName",
            Error::from(ErrorKind::InvalidAlgorithmName).to_string()
        );
    }
}

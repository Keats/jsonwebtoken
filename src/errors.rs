use std::error::Error as StdError;
use std::fmt;
use std::result;

use base64;
use serde_json;

/// A crate private constructor for `Error`.
pub(crate) fn new_error(kind: ErrorKind) -> Error {
    Error(Box::new(kind))
}

/// A type alias for `Result<T, jsonwebtoken::Error>`.
pub type Result<T> = result::Result<T, Error>;

/// An error that can occur when encoding/decoding JWTs
#[derive(Debug)]
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
#[derive(Debug)]
pub enum ErrorKind {
    /// When a token doesn't have a valid JWT shape
    InvalidToken,
    /// When the signature doesn't match
    InvalidSignature,
    /// When the secret given is not a valid ECDSA key
    InvalidEcdsaKey,
    /// When the secret given is not a valid RSA key
    InvalidRsaKey,
    /// When the algorithm from string doesn't match the one passed to `from_str`
    InvalidAlgorithmName,
    /// When a key is provided with an invalid format
    InvalidKeyFormat,

    // Validation errors
    /// When a token’s `exp` claim indicates that it has expired
    ExpiredSignature,
    /// When a token’s `iss` claim does not match the expected issuer
    InvalidIssuer,
    /// When a token’s `aud` claim does not match one of the expected audience values
    InvalidAudience,
    /// When a token’s `aud` claim does not match one of the expected audience values
    InvalidSubject,
    /// When a token’s nbf claim represents a time in the future
    ImmatureSignature,
    /// When the algorithm in the header doesn't match the one passed to `decode`
    InvalidAlgorithm,

    // 3rd party errors
    /// An error happened when decoding some base64 text
    Base64(base64::DecodeError),
    /// An error happened while serializing/deserializing JSON
    Json(serde_json::Error),
    /// Some of the text was invalid UTF-8
    Utf8(::std::string::FromUtf8Error),
    /// Something unspecified went wrong with crypto
    Crypto(::ring::error::Unspecified),

    /// Hints that destructuring should not be exhaustive.
    ///
    /// This enum may grow additional variants, so this makes sure clients
    /// don't count on exhaustive matching. (Otherwise, adding a new variant
    /// could break existing code.)
    #[doc(hidden)]
    __Nonexhaustive,
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self.0 {
            ErrorKind::InvalidToken => "invalid token",
            ErrorKind::InvalidSignature => "invalid signature",
            ErrorKind::InvalidEcdsaKey => "invalid ECDSA key",
            ErrorKind::InvalidRsaKey => "invalid RSA key",
            ErrorKind::ExpiredSignature => "expired signature",
            ErrorKind::InvalidIssuer => "invalid issuer",
            ErrorKind::InvalidAudience => "invalid audience",
            ErrorKind::InvalidSubject => "invalid subject",
            ErrorKind::ImmatureSignature => "immature signature",
            ErrorKind::InvalidAlgorithm => "algorithms don't match",
            ErrorKind::InvalidAlgorithmName => "not a known algorithm",
            ErrorKind::Base64(ref err) => err.description(),
            ErrorKind::Json(ref err) => err.description(),
            ErrorKind::Utf8(ref err) => err.description(),
            ErrorKind::Crypto(ref err) => err.description(),
            _ => unreachable!(),
        }
    }

    fn cause(&self) -> Option<&dyn StdError> {
        match *self.0 {
            ErrorKind::InvalidToken => None,
            ErrorKind::InvalidSignature => None,
            ErrorKind::InvalidEcdsaKey => None,
            ErrorKind::InvalidRsaKey => None,
            ErrorKind::ExpiredSignature => None,
            ErrorKind::InvalidIssuer => None,
            ErrorKind::InvalidAudience => None,
            ErrorKind::InvalidSubject => None,
            ErrorKind::ImmatureSignature => None,
            ErrorKind::InvalidAlgorithm => None,
            ErrorKind::InvalidAlgorithmName => None,
            ErrorKind::Base64(ref err) => Some(err),
            ErrorKind::Json(ref err) => Some(err),
            ErrorKind::Utf8(ref err) => Some(err),
            ErrorKind::Crypto(ref err) => Some(err),
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self.0 {
            ErrorKind::InvalidToken
            | ErrorKind::InvalidSignature
            | ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidRsaKey
            | ErrorKind::ExpiredSignature
            | ErrorKind::InvalidIssuer
            | ErrorKind::InvalidAudience
            | ErrorKind::InvalidSubject
            | ErrorKind::ImmatureSignature
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::InvalidAlgorithmName => write!(f, "{}", self.description()),
            ErrorKind::Json(ref err) => write!(f, "JSON error: {}", err),
            ErrorKind::Utf8(ref err) => write!(f, "UTF-8 error: {}", err),
            ErrorKind::Crypto(ref err) => write!(f, "Crypto error: {}", err),
            _ => unreachable!(),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        new_error(ErrorKind::Base64(err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        new_error(ErrorKind::Json(err))
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

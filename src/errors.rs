use std::{string, fmt, error};
use rustc_serialize::{json, base64};

#[derive(Debug)]
/// All the errors we can encounter while signing/verifying tokens
/// and a couple of custom one for when the token we are trying
/// to verify is invalid
pub enum Error {
    EncodeJSON(json::EncoderError),
    DecodeBase64(base64::FromBase64Error),
    DecodeJSON(json::DecoderError),
    Utf8(string::FromUtf8Error),

    InvalidToken,
    InvalidSignature,
    WrongAlgorithmHeader
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

impl_from_error!(json::EncoderError, Error::EncodeJSON);
impl_from_error!(base64::FromBase64Error, Error::DecodeBase64);
impl_from_error!(json::DecoderError, Error::DecodeJSON);
impl_from_error!(string::FromUtf8Error, Error::Utf8);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::EncodeJSON(ref err) => err.description(),
            Error::DecodeBase64(ref err) => err.description(),
            Error::DecodeJSON(ref err) => err.description(),
            Error::Utf8(ref err) => err.description(),
            Error::InvalidToken => "Invalid Token",
            Error::InvalidSignature => "Invalid Signature",
            Error::WrongAlgorithmHeader => "Wrong Algorithm Header",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(match *self {
            Error::EncodeJSON(ref err) => err as &error::Error,
            Error::DecodeBase64(ref err) => err as &error::Error,
            Error::DecodeJSON(ref err) => err as &error::Error,
            Error::Utf8(ref err) => err as &error::Error,
            ref e => e as &error::Error,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::EncodeJSON(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeJSON(ref err) => fmt::Display::fmt(err, f),
            Error::Utf8(ref err) => fmt::Display::fmt(err, f),
            Error::InvalidToken => write!(f, "{}", error::Error::description(self)),
            Error::InvalidSignature => write!(f, "{}", error::Error::description(self)),
            Error::WrongAlgorithmHeader => write!(f, "{}", error::Error::description(self)),
        }
    }
}

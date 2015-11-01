use std::string;
use rustc_serialize::{json, base64};

#[derive(Debug)]
pub enum Error {
    EncodeJSON(json::EncoderError),
    DecodeBase64(base64::FromBase64Error),
    DecodeJSON(json::DecoderError),
    Utf8(string::FromUtf8Error),
    InvalidToken,
    InvalidSignature
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

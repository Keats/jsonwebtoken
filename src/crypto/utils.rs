//! # Todo
//!
//! - Put in documentation

use crate::{
    algorithms::AlgorithmFamily,
    errors::{new_error, ErrorKind, Result},
    DecodingKey, EncodingKey,
};

pub(crate) fn try_get_hmac_secret_from_encoding_key(encoding_key: &EncodingKey) -> Result<&[u8]> {
    if encoding_key.family == AlgorithmFamily::Hmac {
        Ok(encoding_key.inner())
    } else {
        Err(new_error(ErrorKind::InvalidKeyFormat))
    }
}

pub(crate) fn try_get_hmac_secret_from_decoding_key(decoding_key: &DecodingKey) -> Result<&[u8]> {
    if decoding_key.family != AlgorithmFamily::Hmac {
        return Err(new_error(ErrorKind::InvalidKeyFormat));
    }

    Ok(decoding_key.as_bytes())
}

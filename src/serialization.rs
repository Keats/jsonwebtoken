use base64;
use serde::de::Deserialize;
use serde::ser::Serialize;
use serde_json;


use errors::{Result};
use header::Header;


/// The return type of a successful call to decode(...)
#[derive(Debug)]
pub struct TokenData<T: Deserialize> {
    pub header: Header,
    pub claims: T
}

/// Serializes and encodes to base64
pub fn to_jwt_part<T: Serialize>(input: &T) -> Result<String> {
    let encoded = serde_json::to_string(input)?;
    Ok(base64::encode_config(encoded.as_bytes(), base64::URL_SAFE_NO_PAD))
}

/// Decodes from base64 and deserializes
pub fn from_jwt_part<B: AsRef<str>, T: Deserialize>(encoded: B) -> Result<T> {
    let decoded = base64::decode_config(encoded.as_ref(), base64::URL_SAFE_NO_PAD)?;
    let s = String::from_utf8(decoded)?;

    Ok(serde_json::from_str(&s)?)
}

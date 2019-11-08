use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::map::Map;
use serde_json::{from_str, to_string, Value};

use crate::errors::Result;
use crate::header::Header;

/// The return type of a successful call to decode
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

pub(crate) fn encode(input: &[u8]) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub(crate) fn decode(input: &str) -> Result<Vec<u8>> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD).map_err(|e| e.into())
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = to_string(input)?;
    Ok(encode(json.as_bytes()))
}

/// Decodes from base64 and deserializes from JSON to a struct AND a hashmap of Value so we can
/// run validation on it
pub(crate) fn from_jwt_part_claims<B: AsRef<str>, T: DeserializeOwned>(
    encoded: B,
) -> Result<(T, Map<String, Value>)> {
    let s = String::from_utf8(decode(encoded.as_ref())?)?;

    let claims: T = from_str(&s)?;
    let map: Map<_, _> = from_str(&s)?;
    Ok((claims, map))
}

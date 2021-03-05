use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_json::map::Map;
use serde_json::{from_slice, to_vec, Value};

use crate::errors::Result;

pub(crate) fn b64_encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub(crate) fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD).map_err(|e| e.into())
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = to_vec(input)?;
    Ok(b64_encode(json))
}

/// Decodes from base64 and deserializes from JSON to a struct AND a hashmap of Value so we can
/// run validation on it
pub(crate) fn from_jwt_part_claims<B: AsRef<[u8]>, T: DeserializeOwned>(
    encoded: B,
) -> Result<(T, Map<String, Value>)> {
    let s = b64_decode(encoded)?;

    let claims: T = from_slice(&s)?;
    let validation_map: Map<_, _> = from_slice(&s)?;
    Ok((claims, validation_map))
}

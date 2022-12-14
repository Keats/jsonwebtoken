use serde::{Deserialize, Serialize};

use crate::errors::Result;

const URL_SAFE_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::URL_SAFE,
        base64::engine::fast_portable::NO_PAD,
    );

pub(crate) fn b64_encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::encode_engine(input, &URL_SAFE_ENGINE)
}

pub(crate) fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    base64::decode_engine(input, &URL_SAFE_ENGINE).map_err(|e| e.into())
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String> {
    let json = serde_json::to_vec(input)?;
    Ok(b64_encode(json))
}

/// This is used to decode from base64 then deserialize from JSON to several structs:
/// - The user-provided struct
/// - The ClaimsForValidation struct from this crate to run validation on
pub(crate) struct DecodedJwtPartClaims {
    b64_decoded: Vec<u8>,
}

impl DecodedJwtPartClaims {
    pub fn from_jwt_part_claims(encoded_jwt_part_claims: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self { b64_decoded: b64_decode(encoded_jwt_part_claims)? })
    }

    pub fn deserialize<'a, T: Deserialize<'a>>(&'a self) -> Result<T> {
        Ok(serde_json::from_slice(&self.b64_decoded)?)
    }
}

use base64;
use ring::{digest, hmac};
use ring::constant_time::verify_slices_are_equal;
use serde::de::Deserialize;
use serde::ser::Serialize;
use serde_json;


use errors::{Result, ErrorKind};
use header::Header;


/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512
}

/// Serializes and encodes to base64
fn to_jwt_part<T: Serialize>(input: &T) -> Result<String> {
    let encoded = serde_json::to_string(input)?;
    Ok(base64::encode_config(encoded.as_bytes(), base64::URL_SAFE_NO_PAD))
}

/// Decodes from base64 and deserializes
fn from_jwt_part<B: AsRef<str>, T: Deserialize>(encoded: B) -> Result<T> {
    let decoded = base64::decode_config(encoded.as_ref(), base64::URL_SAFE_NO_PAD)?;
    let s = String::from_utf8(decoded)?;

    Ok(serde_json::from_str(&s)?)
}


/// The return type of a successful call to decode(...)
#[derive(Debug)]
pub struct TokenData<T: Deserialize> {
    pub header: Header,
    pub claims: T
}

/// Take the payload of a JWT and sign it using the algorithm given.
/// Returns the base64 url safe encoded of the hmac result
pub fn sign(data: &str, secret: &[u8], algorithm: Algorithm) -> String {
    let digest = match algorithm {
        Algorithm::HS256 => &digest::SHA256,
        Algorithm::HS384 => &digest::SHA384,
        Algorithm::HS512 => &digest::SHA512,
    };
    let key = hmac::SigningKey::new(digest, secret);
    base64::encode_config(
        hmac::sign(&key, data.as_bytes()).as_ref(),
        base64::URL_SAFE_NO_PAD
    )
}

/// Compares the signature given with a re-computed signature
pub fn verify(signature: &str, data: &str, secret: &[u8], algorithm: Algorithm) -> bool {
    verify_slices_are_equal(signature.as_ref(), sign(data, secret, algorithm).as_ref()).is_ok()
}

/// Encode the claims passed and sign the payload using the algorithm from the header and the secret
pub fn encode<T: Serialize>(header: Header, claims: &T, secret: &[u8]) -> Result<String> {
    let encoded_header = to_jwt_part(&header)?;
    let encoded_claims = to_jwt_part(&claims)?;
    let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*payload, secret.as_ref(), header.alg);

    Ok([payload, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(ErrorKind::InvalidToken.into())
        }
    }}
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Deserialize>(token: &str, secret: &[u8], algorithm: Algorithm) -> Result<TokenData<T>> {
    let (signature, payload) = expect_two!(token.rsplitn(2, '.'));

    if !verify(signature, payload, secret, algorithm) {
        return Err(ErrorKind::InvalidSignature.into());
    }

    let (claims, header) = expect_two!(payload.rsplitn(2, '.'));

    let header: Header = from_jwt_part(header)?;
    if header.alg != algorithm {
        return Err(ErrorKind::WrongAlgorithmHeader.into());
    }
    let decoded_claims: T = from_jwt_part(claims)?;

    Ok(TokenData { header: header, claims: decoded_claims })
}

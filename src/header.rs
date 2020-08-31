use serde::{Deserialize, Serialize};

use crate::algorithms::Algorithm;
use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::b64_decode;

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: Algorithm,
    /// Content type
    ///
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// JSON Key URL
    ///
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// Key ID
    ///
    /// Defined in [RFC7515#4.1.4](https://tools.ietf.org/html/rfc7515#section-4.1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL
    ///
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// Critical
    ///
    /// Defined in [RFC7515#4.1.11](https://tools.ietf.org/html/rfc7515#section-4.1.11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Additional Public or Private header parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub params: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl Header {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Self {
        Header {
            typ: Some("JWT".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
            crit: None,
            params: None,
        }
    }

    /// Converts an encoded part into the Header struct if possible
    pub(crate) fn from_encoded(encoded_part: &str) -> Result<Self> {
        let decoded = b64_decode(encoded_part)?;
        let s = String::from_utf8(decoded)?;
        let header: Header = serde_json::from_str(&s)?;

        if let Some(crit) = &header.crit {
            if crit.is_empty() {
                return Err(new_error(ErrorKind::InvalidCriticalHeader));
            }
            for name in crit {
                match name.as_str() {
                    "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ"
                    | "cty" | "crit" => return Err(new_error(ErrorKind::InvalidCriticalHeader)),
                    _ => {
                        let has = match &header.params {
                            Some(params) => params.contains_key(name),
                            None => false,
                        };
                        if !has {
                            return Err(new_error(ErrorKind::InvalidCriticalHeader));
                        }
                    }
                }
            }
        }

        Ok(header)
    }
}

impl Default for Header {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        Header::new(Algorithm::default())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn additional_parameters() {
        let header_json = r###"{
            "alg": "ES256",
            "example": 123
        }"###;
        let header_b64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let res = Header::from_encoded(&header_b64);
        let header = res.unwrap();
        assert_eq!(header.params.unwrap().get("example").unwrap(), 123);
    }

    #[test]
    fn crit_invalid_fails() {
        let header_json = r###"{
            "alg": "ES256",
            "crit": ["alg"]
        }"###;
        let header_b64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let res = Header::from_encoded(&header_b64);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidCriticalHeader => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn crit_missing_fails() {
        let header_json = r###"{
            "alg": "ES256",
            "crit": ["b64"]
        }"###;
        let header_b64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let res = Header::from_encoded(&header_b64);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidCriticalHeader => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn crit_present_ok() {
        let header_json = r###"{
            "alg": "ES256",
            "crit": ["b64"],
            "b64": false
        }"###;
        let header_b64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let res = Header::from_encoded(&header_b64);
        assert!(res.is_ok());
    }
}

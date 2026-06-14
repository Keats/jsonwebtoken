use std::collections::BTreeMap;
use std::result;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::jwk::Jwk;
use crate::serialization::b64_decode;

const ZIP_SERIAL_DEFLATE: &str = "DEF";
const ENC_A128CBC_HS256: &str = "A128CBC-HS256";
const ENC_A192CBC_HS384: &str = "A192CBC-HS384";
const ENC_A256CBC_HS512: &str = "A256CBC-HS512";
const ENC_A128GCM: &str = "A128GCM";
const ENC_A192GCM: &str = "A192GCM";
const ENC_A256GCM: &str = "A256GCM";

/// Encryption algorithm for encrypted payloads.
///
/// Defined in [RFC7516#4.1.2](https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2).
///
/// Values defined in [RFC7518#5.1](https://datatracker.ietf.org/doc/html/rfc7518#section-5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub enum Enc {
    A128CBC_HS256,
    A192CBC_HS384,
    A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,
    Other(String),
}

impl Serialize for Enc {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Enc::A128CBC_HS256 => ENC_A128CBC_HS256,
            Enc::A192CBC_HS384 => ENC_A192CBC_HS384,
            Enc::A256CBC_HS512 => ENC_A256CBC_HS512,
            Enc::A128GCM => ENC_A128GCM,
            Enc::A192GCM => ENC_A192GCM,
            Enc::A256GCM => ENC_A256GCM,
            Enc::Other(v) => v,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Enc {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            ENC_A128CBC_HS256 => return Ok(Enc::A128CBC_HS256),
            ENC_A192CBC_HS384 => return Ok(Enc::A192CBC_HS384),
            ENC_A256CBC_HS512 => return Ok(Enc::A256CBC_HS512),
            ENC_A128GCM => return Ok(Enc::A128GCM),
            ENC_A192GCM => return Ok(Enc::A192GCM),
            ENC_A256GCM => return Ok(Enc::A256GCM),
            _ => (),
        }
        Ok(Enc::Other(s))
    }
}

/// Compression applied to plaintext.
///
/// Defined in [RFC7516#4.1.3](https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Zip {
    Deflate,
    Other(String),
}

impl Serialize for Zip {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Zip::Deflate => ZIP_SERIAL_DEFLATE,
            Zip::Other(v) => v,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Zip {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            ZIP_SERIAL_DEFLATE => Ok(Zip::Deflate),
            _ => Ok(Zip::Other(s)),
        }
    }
}

/// Any additional non-standard headers not defined in [RFC7515#4.1](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1).
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extras {
    #[serde(flatten)]
    inner: BTreeMap<String, serde_json::Value>,
}

impl Extras {
    /// Try to get the value to a given key, deserialized as `T`
    pub fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        match self.inner.get(key) {
            Some(value) => {
                let parsed = serde_json::from_value(value.clone())?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    /// Add the given (key, value) pair to the header
    pub fn insert<T>(&mut self, key: impl Into<String>, value: T)
    where
        T: Serialize,
    {
        let value =
            serde_json::to_value(value).expect("serializing extra header value must not fail");
        self.inner.insert(key.into(), value);
    }

    /// Get the raw extra values specified in the header
    pub fn inner(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.inner
    }
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
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
    /// JSON Web Key
    ///
    /// Defined in [RFC7515#4.1.3](https://tools.ietf.org/html/rfc7515#section-4.1.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
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
    /// X.509 certificate chain. A Vec of base64 encoded ASN.1 DER certificates.
    ///
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X.509 SHA1 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// X.509 SHA256 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.8](https://tools.ietf.org/html/rfc7515#section-4.1.8).
    ///
    /// This will be serialized/deserialized as "x5t#S256", as defined by the RFC.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
    /// Critical - indicates header fields that must be understood by the receiver.
    ///
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// See `Enc` for description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<Enc>,
    /// See `Zip` for description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Zip>,
    /// ACME: The URL to which this JWS object is directed
    ///
    /// Defined in [RFC8555#6.4](https://datatracker.ietf.org/doc/html/rfc8555#section-6.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// ACME: Random data for preventing replay attacks.
    ///
    /// Defined in [RFC8555#6.5.2](https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Any additional non-standard headers not defined in [RFC7515#4.1](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1).
    /// Once serialized, all keys will be converted to fields at the root level of the header payload
    /// Ex: Dict("custom" -> "header") will be converted to "{"typ": "JWT", ..., "custom": "header"}"
    #[serde(flatten)]
    pub extras: Extras,
}

impl Header {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Self {
        Header {
            typ: Some("JWT".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            crit: None,
            enc: None,
            zip: None,
            url: None,
            nonce: None,
            extras: Extras::default(),
        }
    }

    /// Converts an encoded part into the Header struct if possible
    pub(crate) fn from_encoded<T: AsRef<[u8]>>(encoded_part: T) -> Result<Self> {
        let decoded = b64_decode(encoded_part)?;
        Ok(serde_json::from_slice(&decoded)?)
    }

    /// Decodes the X.509 certificate chain into ASN.1 DER format.
    pub fn x5c_der(&self) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(self
            .x5c
            .as_ref()
            .map(|b64_certs| {
                b64_certs.iter().map(|x| STANDARD.decode(x)).collect::<result::Result<_, _>>()
            })
            .transpose()?)
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
    use std::hash::{DefaultHasher, Hash, Hasher};

    use crate::{Algorithm, Extras, Header};

    fn hash<T>(value: &T) -> u64
    where
        T: Hash,
    {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_header_extras_hash() {
        assert_eq!(hash(&Extras::default()), hash(&Extras::default()));

        let mut a = Extras::default();
        a.insert("foo", "bar");
        a.insert("answer", 42);

        let mut b = Extras::default();
        b.insert("answer", 42);
        b.insert("foo", "bar");

        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));

        b.insert("more", "values");

        assert_ne!(a, b);
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn test_header_hash() {
        assert_eq!(hash(&Header::default()), hash(&Header::default()));

        let mut extras_a = Extras::default();
        extras_a.insert("foo", "bar");
        extras_a.insert("answer", 42);

        let mut extras_b = Extras::default();
        extras_b.insert("answer", 42);
        extras_b.insert("foo", "bar");

        let mut a = Header::new(Algorithm::HS512);
        a.extras = extras_a;

        let mut b = Header::new(Algorithm::HS512);
        b.extras = extras_b.clone();

        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));

        extras_b.insert("more", "values");
        b.extras = extras_b;

        assert_ne!(a, b);
        assert_ne!(hash(&a), hash(&b));

        assert_ne!(
            hash(&Header { alg: Algorithm::EdDSA, ..Default::default() }),
            hash(&Header { alg: Algorithm::ES256, ..Default::default() })
        )
    }
}

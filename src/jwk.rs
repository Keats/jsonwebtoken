#![allow(missing_docs)]
//! This crate contains types only for working JWK and JWK Sets
//! This is only meant to be used to deal with public JWK, not generate ones.
//! Most of the code in this file is taken from https://github.com/lawliet89/biscuit but
//! tweaked to remove the private bits as it's not the goal for this crate currently.

use crate::{
    errors::{self, Error, ErrorKind},
    Algorithm,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

/// The intended usage of the public `KeyType`. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PublicKeyUse {
    /// Indicates a public key is meant for signature verification
    Signature,
    /// Indicates a public key is meant for encryption
    Encryption,
    /// Other usage
    Other(String),
}

impl Serialize for PublicKeyUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match self {
            PublicKeyUse::Signature => "sig",
            PublicKeyUse::Encryption => "enc",
            PublicKeyUse::Other(other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for PublicKeyUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyUseVisitor;
        impl<'de> de::Visitor<'de> for PublicKeyUseVisitor {
            type Value = PublicKeyUse;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sig" => PublicKeyUse::Signature,
                    "enc" => PublicKeyUse::Encryption,
                    other => PublicKeyUse::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(PublicKeyUseVisitor)
    }
}

/// Operations that the key is intended to be used for. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum KeyOperations {
    /// Computer digital signature or MAC
    Sign,
    /// Verify digital signature or MAC
    Verify,
    /// Encrypt content
    Encrypt,
    /// Decrypt content and validate decryption, if applicable
    Decrypt,
    /// Encrypt key
    WrapKey,
    /// Decrypt key and validate decryption, if applicable
    UnwrapKey,
    /// Derive key
    DeriveKey,
    /// Derive bits not to be used as a key
    DeriveBits,
    /// Other operation
    Other(String),
}

impl Serialize for KeyOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match self {
            KeyOperations::Sign => "sign",
            KeyOperations::Verify => "verify",
            KeyOperations::Encrypt => "encrypt",
            KeyOperations::Decrypt => "decrypt",
            KeyOperations::WrapKey => "wrapKey",
            KeyOperations::UnwrapKey => "unwrapKey",
            KeyOperations::DeriveKey => "deriveKey",
            KeyOperations::DeriveBits => "deriveBits",
            KeyOperations::Other(other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for KeyOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyOperationsVisitor;
        impl<'de> de::Visitor<'de> for KeyOperationsVisitor {
            type Value = KeyOperations;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sign" => KeyOperations::Sign,
                    "verify" => KeyOperations::Verify,
                    "encrypt" => KeyOperations::Encrypt,
                    "decrypt" => KeyOperations::Decrypt,
                    "wrapKey" => KeyOperations::WrapKey,
                    "unwrapKey" => KeyOperations::UnwrapKey,
                    "deriveKey" => KeyOperations::DeriveKey,
                    "deriveBits" => KeyOperations::DeriveBits,
                    other => KeyOperations::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(KeyOperationsVisitor)
    }
}

/// The algorithms of the keys
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// ECDSA using SHA-256
    ES256,
    /// ECDSA using SHA-384
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,

    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,

    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    EdDSA,

    /// RSAES-PKCS1-V1_5
    RSA1_5,

    /// RSAES-OAEP using SHA-1
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,

    /// RSAES-OAEP-256 using SHA-2
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,
}

impl FromStr for KeyAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> errors::Result<Self> {
        match s {
            "HS256" => Ok(KeyAlgorithm::HS256),
            "HS384" => Ok(KeyAlgorithm::HS384),
            "HS512" => Ok(KeyAlgorithm::HS512),
            "ES256" => Ok(KeyAlgorithm::ES256),
            "ES384" => Ok(KeyAlgorithm::ES384),
            "RS256" => Ok(KeyAlgorithm::RS256),
            "RS384" => Ok(KeyAlgorithm::RS384),
            "PS256" => Ok(KeyAlgorithm::PS256),
            "PS384" => Ok(KeyAlgorithm::PS384),
            "PS512" => Ok(KeyAlgorithm::PS512),
            "RS512" => Ok(KeyAlgorithm::RS512),
            "EdDSA" => Ok(KeyAlgorithm::EdDSA),
            "RSA1_5" => Ok(KeyAlgorithm::RSA1_5),
            "RSA-OAEP" => Ok(KeyAlgorithm::RSA_OAEP),
            "RSA-OAEP-256" => Ok(KeyAlgorithm::RSA_OAEP_256),
            _ => Err(ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl KeyAlgorithm {
    fn to_algorithm(self) -> errors::Result<Algorithm> {
        Algorithm::from_str(self.to_string().as_str())
    }
}

/// Common JWK parameters
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct CommonParameters {
    /// The intended use of the public key. Should not be specified with `key_operations`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none", default)]
    pub public_key_use: Option<PublicKeyUse>,

    /// The "key_ops" (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.  The "key_ops" parameter is
    /// intended for use cases in which public, private, or symmetric keys
    /// may be present.
    /// Should not be specified with `public_key_use`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "key_ops", skip_serializing_if = "Option::is_none", default)]
    pub key_operations: Option<Vec<KeyOperations>>,

    /// The algorithm keys intended for use with the key.
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none", default)]
    pub key_algorithm: Option<KeyAlgorithm>,

    /// The case sensitive Key ID for the key
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,

    /// X.509 Public key certificate URL. This is currently not implemented (correctly).
    ///
    /// Serialized to `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    ///
    /// Serialized to `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate SHA1 thumbprint. This is currently not implemented (correctly).
    ///
    /// Serialized to `x5t`.
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_sha1_fingerprint: Option<String>,

    /// X.509 Certificate SHA256 thumbprint. This is currently not implemented (correctly).
    ///
    /// Serialized to `x5t#S256`.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x509_sha256_fingerprint: Option<String>,
}

/// Key type value for an Elliptic Curve Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum EllipticCurveKeyType {
    /// Key type value for an Elliptic Curve Key.
    #[default]
    EC,
}

/// Type of cryptographic curve used by a key. This is defined in
/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum EllipticCurve {
    /// P-256 curve
    #[serde(rename = "P-256")]
    #[default]
    P256,
    /// P-384 curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 curve -- unsupported by `ring`.
    #[serde(rename = "P-521")]
    P521,
    /// Ed25519 curve
    #[serde(rename = "Ed25519")]
    Ed25519,
}

/// Parameters for an Elliptic Curve Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct EllipticCurveKeyParameters {
    /// Key type value for an Elliptic Curve Key.
    #[serde(rename = "kty")]
    pub key_type: EllipticCurveKeyType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" (x coordinate) parameter contains the x coordinate for the
    /// Elliptic Curve point.
    pub x: String,
    /// The "y" (y coordinate) parameter contains the y coordinate for the
    /// Elliptic Curve point.
    pub y: String,
}

/// Key type value for an RSA Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum RSAKeyType {
    /// Key type value for an RSA Key.
    #[default]
    RSA,
}

/// Parameters for a RSA Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct RSAKeyParameters {
    /// Key type value for a RSA Key
    #[serde(rename = "kty")]
    pub key_type: RSAKeyType,

    /// The "n" (modulus) parameter contains the modulus value for the RSA
    /// public key.
    pub n: String,

    /// The "e" (exponent) parameter contains the exponent value for the RSA
    /// public key.
    pub e: String,
}

/// Key type value for an Octet symmetric key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum OctetKeyType {
    /// Key type value for an Octet symmetric key.
    #[serde(rename = "oct")]
    #[default]
    Octet,
}

/// Parameters for an Octet Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct OctetKeyParameters {
    /// Key type value for an Octet Key
    #[serde(rename = "kty")]
    pub key_type: OctetKeyType,
    /// The octet key value
    #[serde(rename = "k")]
    pub value: String,
}

/// Key type value for an Octet Key Pair.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum OctetKeyPairType {
    /// Key type value for an Octet Key Pair.
    #[serde(rename = "OKP")]
    #[default]
    OctetKeyPair,
}

/// Parameters for an Octet Key Pair
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct OctetKeyPairParameters {
    /// Key type value for an Octet Key Pair
    #[serde(rename = "kty")]
    pub key_type: OctetKeyPairType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" parameter contains the base64 encoded public key
    pub x: String,
}

/// Algorithm specific parameters
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
pub enum AlgorithmParameters {
    EllipticCurve(EllipticCurveKeyParameters),
    RSA(RSAKeyParameters),
    OctetKey(OctetKeyParameters),
    OctetKeyPair(OctetKeyPairParameters),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct Jwk {
    #[serde(flatten)]
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    #[serde(flatten)]
    pub algorithm: AlgorithmParameters,
}

impl Jwk {
    /// Find whether the Algorithm is implemented and supported
    pub fn is_supported(&self) -> bool {
        self.common.key_algorithm.unwrap().to_algorithm().is_ok()
    }
}

/// A JWK set
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Find the key in the set that matches the given key id, if any.
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys
            .iter()
            .find(|jwk| jwk.common.key_id.is_some() && jwk.common.key_id.as_ref().unwrap() == kid)
    }
}

#[cfg(test)]
mod tests {
    use crate::jwk::{AlgorithmParameters, JwkSet, OctetKeyType};
    use crate::serialization::b64_encode;
    use crate::Algorithm;
    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[test]
    #[wasm_bindgen_test]
    fn check_hs256() {
        let key = b64_encode("abcdefghijklmnopqrstuvwxyz012345");
        let jwks_json = json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "kid": "abc123",
                    "k": key
                }
            ]
        });

        let set: JwkSet = serde_json::from_value(jwks_json).expect("Failed HS256 check");
        assert_eq!(set.keys.len(), 1);
        let key = &set.keys[0];
        assert_eq!(key.common.key_id, Some("abc123".to_string()));
        let algorithm = key.common.key_algorithm.unwrap().to_algorithm().unwrap();
        assert_eq!(algorithm, Algorithm::HS256);

        match &key.algorithm {
            AlgorithmParameters::OctetKey(key) => {
                assert_eq!(key.key_type, OctetKeyType::Octet);
                assert_eq!(key.value, key.value)
            }
            _ => panic!("Unexpected key algorithm"),
        }
    }
}

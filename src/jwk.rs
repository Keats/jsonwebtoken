#![allow(missing_docs)]
///! This crate contains types only for working JWK and JWK Sets
///! This is only meant to be used to deal with public JWK, not generate ones.
///! Most of the code in this file is taken from https://github.com/lawliet89/biscuit but
/// tweaked to remove the private bits as it's not the goal for this crate currently.
///!

use crate::Algorithm;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;


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
        let string = match *self {
            PublicKeyUse::Signature => "sig",
            PublicKeyUse::Encryption => "enc",
            PublicKeyUse::Other(ref other) => other,
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
        let string = match *self {
            KeyOperations::Sign => "sign",
            KeyOperations::Verify => "verify",
            KeyOperations::Encrypt => "encrypt",
            KeyOperations::Decrypt => "decrypt",
            KeyOperations::WrapKey => "wrapKey",
            KeyOperations::UnwrapKey => "unwrapKey",
            KeyOperations::DeriveKey => "deriveKey",
            KeyOperations::DeriveBits => "deriveBits",
            KeyOperations::Other(ref other) => other,
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

/// Common JWK parameters
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
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

    /// The algorithm intended for use with the key
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<Algorithm>,

    /// The case sensitive Key ID for the key
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,
}

/// Key type value for an Elliptic Curve Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EllipticCurveKeyType {
    /// Key type value for an Elliptic Curve Key.
    EC,
}

impl Default for EllipticCurveKeyType {
    fn default() -> Self {
        EllipticCurveKeyType::EC
    }
}

/// Type of cryptographic curve used by a key. This is defined in
/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EllipticCurve {
    /// P-256 curve
    #[serde(rename = "P-256")]
    P256,
    /// P-384 curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 curve -- unsupported by `ring`.
    #[serde(rename = "P-521")]
    P521,
}

impl Default for EllipticCurve {
    fn default() -> Self {
        EllipticCurve::P256
    }
}

/// Parameters for an Elliptic Curve Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RSAKeyType {
    /// Key type value for an RSA Key.
    RSA,
}

impl Default for RSAKeyType {
    fn default() -> Self {
        RSAKeyType::RSA
    }
}

/// Parameters for a RSA Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OctetKeyType {
    /// Key type value for an Octet symmetric key.
    #[serde(rename = "oct")]
    Octet,
}

impl Default for OctetKeyType {
    fn default() -> Self {
        OctetKeyType::Octet
    }
}

/// Parameters for an Octet Key
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OctetKeyParameters {
    /// Key type value for an Octet Key
    #[serde(rename = "kty")]
    pub key_type: OctetKeyType,
    /// The octet key value
    pub value: String,
}

/// Key type value for an Octet Key Pair.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OctetKeyPairType {
    /// Key type value for an Octet Key Pair.
    #[serde(rename = "OKP")]
    OctetKeyPair,
}

impl Default for OctetKeyPairType {
    fn default() -> Self {
        OctetKeyPairType::OctetKeyPair
    }
}

/// Parameters for an Octet Key Pair
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmParameters {
    EllipticCurve(EllipticCurveKeyParameters),
    RSA(RSAKeyParameters),
    OctetKey(OctetKeyParameters),
    OctetKeyPair(OctetKeyPairParameters),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(flatten)]
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    #[serde(flatten)]
    pub algorithm: AlgorithmParameters,
}

/// A JWK set
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

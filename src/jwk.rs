//! This crate contains types only for working JWK and JWK Sets
//! This is only meant to be used to deal with public JWK, not generate ones.
//! Most of the code in this file is taken from <https://github.com/lawliet89/biscuit> but
//! tweaked to remove the private bits as it's not the goal for this crate currently.

use std::collections::BTreeMap;
use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::algorithms::{
    ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_87_PUBLIC_KEY_LEN,
};
use crate::crypto::{CryptoProvider, ec_pub_components_from_public_key};
use crate::errors::{self, Error, ErrorKind, new_error};
use crate::serialization::b64_encode;
use crate::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey, decoding::DecodingKeyKind};

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
        impl de::Visitor<'_> for PublicKeyUseVisitor {
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
        impl de::Visitor<'_> for KeyOperationsVisitor {
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
#[non_exhaustive]
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

    /// ML-DSA-44 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-44")]
    MLDSA44,
    /// ML-DSA-65 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-65")]
    MLDSA65,
    /// ML-DSA-87 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-87")]
    MLDSA87,

    /// Catch-All for when the key algorithm can not be determined or is not supported
    #[serde(other)]
    UNKNOWN_ALGORITHM,
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
            "ML-DSA-44" => Ok(KeyAlgorithm::MLDSA44),
            "ML-DSA-65" => Ok(KeyAlgorithm::MLDSA65),
            "ML-DSA-87" => Ok(KeyAlgorithm::MLDSA87),
            _ => Err(ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl From<Algorithm> for KeyAlgorithm {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::HS256 => KeyAlgorithm::HS256,
            Algorithm::HS384 => KeyAlgorithm::HS384,
            Algorithm::HS512 => KeyAlgorithm::HS512,
            Algorithm::ES256 => KeyAlgorithm::ES256,
            Algorithm::ES384 => KeyAlgorithm::ES384,
            Algorithm::RS256 => KeyAlgorithm::RS256,
            Algorithm::RS384 => KeyAlgorithm::RS384,
            Algorithm::RS512 => KeyAlgorithm::RS512,
            Algorithm::PS256 => KeyAlgorithm::PS256,
            Algorithm::PS384 => KeyAlgorithm::PS384,
            Algorithm::PS512 => KeyAlgorithm::PS512,
            Algorithm::EdDSA => KeyAlgorithm::EdDSA,
            Algorithm::MLDSA44 => KeyAlgorithm::MLDSA44,
            Algorithm::MLDSA65 => KeyAlgorithm::MLDSA65,
            Algorithm::MLDSA87 => KeyAlgorithm::MLDSA87,
        }
    }
}

impl TryFrom<KeyAlgorithm> for Algorithm {
    type Error = Error;

    fn try_from(alg: KeyAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            KeyAlgorithm::HS256 => Ok(Algorithm::HS256),
            KeyAlgorithm::HS384 => Ok(Algorithm::HS384),
            KeyAlgorithm::HS512 => Ok(Algorithm::HS512),
            KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
            KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
            KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
            KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
            KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
            KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
            KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
            KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
            KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
            KeyAlgorithm::MLDSA44 => Ok(Algorithm::MLDSA44),
            KeyAlgorithm::MLDSA65 => Ok(Algorithm::MLDSA65),
            KeyAlgorithm::MLDSA87 => Ok(Algorithm::MLDSA87),
            _ => Err(new_error(ErrorKind::UnsupportedAlgorithm)),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyAlgorithm::MLDSA44 => write!(f, "ML-DSA-44"),
            KeyAlgorithm::MLDSA65 => write!(f, "ML-DSA-65"),
            KeyAlgorithm::MLDSA87 => write!(f, "ML-DSA-87"),
            other => write!(f, "{:?}", other),
        }
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

    /// The `key_ops` (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.  The `key_ops` parameter is
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
#[non_exhaustive]
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

/// Parameters for unknown keys
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct OtherKeyParameters {
    #[serde(flatten)]
    #[allow(missing_docs)]
    pub fields: BTreeMap<String, serde_json::Value>,
}

/// Key type value for an AKP.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum AKPKeyType {
    /// Key type value for an AKP.
    #[default]
    AKP,
}

/// Parameters for an AKP
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
pub struct AKPKeyParameters {
    /// Key type value for an AKP
    #[serde(rename = "kty")]
    pub key_type: AKPKeyType,

    /// The "priv" parameter contains the private key.
    /// It is optional since public JWKs do not carry it.
    /// Underscore is used since "priv" is a rust keyword.
    #[serde(rename = "priv", skip_serializing_if = "Option::is_none", default)]
    pub priv_: Option<String>,

    /// The "pub" parameter contains the public key.
    /// Underscore is used since "pub" is a rust keyword.
    #[serde(rename = "pub")]
    pub pub_: String,
}

/// Algorithm specific parameters
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(untagged)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum AlgorithmParameters {
    EllipticCurve(EllipticCurveKeyParameters),
    RSA(RSAKeyParameters),
    OctetKey(OctetKeyParameters),
    OctetKeyPair(OctetKeyPairParameters),
    AlgorithmKeyPair(AKPKeyParameters),
    Other(OtherKeyParameters),
}

/// The function to use to hash the intermediate thumbprint data.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ThumbprintHash {
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Hash)]
#[allow(missing_docs)]
pub struct Jwk {
    #[serde(flatten)]
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    #[serde(flatten)]
    pub algorithm: AlgorithmParameters,
}

/// Serde helper used to validate algorithm-specific fields after deserialization.
#[derive(Deserialize)]
struct JwkWire {
    #[serde(flatten)]
    common: CommonParameters,
    #[serde(flatten)]
    algorithm: AlgorithmParameters,
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let JwkWire { common, algorithm } = JwkWire::deserialize(deserializer)?;

        if let AlgorithmParameters::AlgorithmKeyPair(_) = &algorithm {
            common.key_algorithm.ok_or_else(|| de::Error::missing_field("alg"))?;
        }

        Ok(Jwk { common, algorithm })
    }
}

impl Jwk {
    /// Find whether the Algorithm is implemented and supported
    pub fn is_supported(&self) -> bool {
        match &self.algorithm {
            AlgorithmParameters::AlgorithmKeyPair(_) => self
                .common
                .key_algorithm
                .and_then(|alg| Algorithm::try_from(alg).ok())
                .is_some_and(|alg| alg.family() == AlgorithmFamily::Mldsa),
            _ => match self.common.key_algorithm {
                Some(alg) => alg.to_algorithm().is_ok(),
                None => false,
            },
        }
    }

    /// Create a `JWK` from an `EncodingKey`.
    pub fn from_encoding_key(key: &EncodingKey, alg: Algorithm) -> errors::Result<Self> {
        Ok(Self {
            common: CommonParameters { key_algorithm: Some(alg.into()), ..Default::default() },
            algorithm: match key.family() {
                AlgorithmFamily::Hmac => AlgorithmParameters::OctetKey(OctetKeyParameters {
                    key_type: OctetKeyType::Octet,
                    value: b64_encode(key.as_bytes()),
                }),
                AlgorithmFamily::Rsa => {
                    let (n, e) = (CryptoProvider::get_default()
                        .key_utils
                        .rsa_pub_components_from_private_key)(
                        key.as_bytes()
                    )?;
                    AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: RSAKeyType::RSA,
                        n: b64_encode(n),
                        e: b64_encode(e),
                    })
                }
                AlgorithmFamily::Ec => {
                    let (curve, x, y) = (CryptoProvider::get_default()
                        .key_utils
                        .ec_pub_components_from_private_key)(
                        key.as_bytes(), alg
                    )?;
                    AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                        key_type: EllipticCurveKeyType::EC,
                        curve,
                        x: b64_encode(x),
                        y: b64_encode(y),
                    })
                }
                AlgorithmFamily::Ed => {
                    // Get the curve type based off the encoding key length
                    // Note: here we will receive a DER key which contains a 16 byte ANS.1 header
                    let curve_type: EllipticCurve = match key.as_bytes().len() {
                        // 16 byte header + 32 byte Ed25519 key
                        48 => Ok(EllipticCurve::Ed25519),
                        _ => Err(Error::from(ErrorKind::InvalidEddsaKey)),
                    }?;

                    // Extract the public key from the encoding key
                    let public_key_bytes = (CryptoProvider::get_default()
                        .key_utils
                        .ed_pub_components_from_private_key)(
                        key.as_bytes(), &curve_type
                    )?;

                    AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                        key_type: OctetKeyPairType::OctetKeyPair,
                        curve: curve_type,
                        x: b64_encode(public_key_bytes),
                    })
                }
                AlgorithmFamily::Mldsa => {
                    let public_key_bytes = (CryptoProvider::get_default()
                        .key_utils
                        .mldsa_pub_components_from_private_key)(
                        key.as_bytes(), alg
                    )?;

                    AlgorithmParameters::AlgorithmKeyPair(AKPKeyParameters {
                        key_type: AKPKeyType::AKP,
                        priv_: None,
                        pub_: b64_encode(public_key_bytes),
                    })
                }
            },
        })
    }

    /// Create a `JWK` from a `DecodingKey`.
    pub fn from_decoding_key(
        key: &DecodingKey,
        alg: Option<Algorithm>,
    ) -> crate::errors::Result<Self> {
        Ok(Self {
            common: CommonParameters { key_algorithm: alg.map(|a| a.into()), ..Default::default() },
            algorithm: match key.family() {
                crate::algorithms::AlgorithmFamily::Hmac => {
                    AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: OctetKeyType::Octet,
                        value: b64_encode(key.try_get_as_bytes()?),
                    })
                }
                crate::algorithms::AlgorithmFamily::Rsa => {
                    let (n, e) = match &key.kind() {
                        DecodingKeyKind::RsaModulusExponent { n, e } => {
                            (b64_encode(n), b64_encode(e))
                        }
                        DecodingKeyKind::SecretOrDer(der) => {
                            let (n, e) = (CryptoProvider::get_default()
                                .key_utils
                                .rsa_pub_components_from_public_key)(
                                der
                            )?;
                            (b64_encode(n), b64_encode(e))
                        }
                    };

                    AlgorithmParameters::RSA(RSAKeyParameters { key_type: RSAKeyType::RSA, n, e })
                }
                crate::algorithms::AlgorithmFamily::Ec => {
                    let (curve, x, y) = ec_pub_components_from_public_key(key.try_get_as_bytes()?)?;
                    AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                        key_type: EllipticCurveKeyType::EC,
                        curve,
                        x: b64_encode(x),
                        y: b64_encode(y),
                    })
                }
                crate::algorithms::AlgorithmFamily::Ed => {
                    let pub_bytes = key.try_get_as_bytes()?;
                    let (curve_type, x) = match pub_bytes.len() {
                        // ED25519: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
                        32 => (EllipticCurve::Ed25519, pub_bytes),
                        _ => return Err(ErrorKind::InvalidEddsaKey.into()),
                    };

                    AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                        key_type: OctetKeyPairType::OctetKeyPair,
                        curve: curve_type,
                        x: b64_encode(x),
                    })
                }
                crate::algorithms::AlgorithmFamily::Mldsa => {
                    let alg = alg.ok_or_else(|| new_error(ErrorKind::InvalidAlgorithm))?;
                    let expected_len = match alg {
                        Algorithm::MLDSA44 => ML_DSA_44_PUBLIC_KEY_LEN,
                        Algorithm::MLDSA65 => ML_DSA_65_PUBLIC_KEY_LEN,
                        Algorithm::MLDSA87 => ML_DSA_87_PUBLIC_KEY_LEN,
                        _ => return Err(new_error(ErrorKind::InvalidAlgorithm)),
                    };
                    let pub_bytes = key.try_get_as_bytes()?;
                    if pub_bytes.len() != expected_len {
                        return Err(new_error(ErrorKind::InvalidKeyFormat));
                    }

                    AlgorithmParameters::AlgorithmKeyPair(AKPKeyParameters {
                        key_type: AKPKeyType::AKP,
                        priv_: None,
                        pub_: b64_encode(pub_bytes),
                    })
                }
            },
        })
    }

    /// Compute the thumbprint of the JWK.
    ///
    /// Per [RFC-7638](https://datatracker.ietf.org/doc/html/rfc7638)
    pub fn thumbprint(&self, hash_function: ThumbprintHash) -> errors::Result<String> {
        let pre = match &self.algorithm {
            AlgorithmParameters::EllipticCurve(a) => match a.curve {
                EllipticCurve::P256 | EllipticCurve::P384 | EllipticCurve::P521 => {
                    format!(
                        r#"{{"crv":{},"kty":{},"x":"{}","y":"{}"}}"#,
                        serde_json::to_string(&a.curve).unwrap(),
                        serde_json::to_string(&a.key_type).unwrap(),
                        a.x,
                        a.y,
                    )
                }
                EllipticCurve::Ed25519 => {
                    return Err(ErrorKind::InvalidKeyFormat.into());
                }
            },
            AlgorithmParameters::RSA(a) => {
                format!(
                    r#"{{"e":"{}","kty":{},"n":"{}"}}"#,
                    a.e,
                    serde_json::to_string(&a.key_type).unwrap(),
                    a.n,
                )
            }
            AlgorithmParameters::OctetKey(a) => {
                format!(
                    r#"{{"k":"{}","kty":{}}}"#,
                    a.value,
                    serde_json::to_string(&a.key_type).unwrap()
                )
            }
            AlgorithmParameters::OctetKeyPair(a) => match a.curve {
                EllipticCurve::P256 | EllipticCurve::P384 | EllipticCurve::P521 => {
                    return Err(ErrorKind::InvalidKeyFormat.into());
                }
                EllipticCurve::Ed25519 => {
                    format!(
                        r#"{{"crv":{},"kty":{},"x":"{}"}}"#,
                        serde_json::to_string(&a.curve).unwrap(),
                        serde_json::to_string(&a.key_type).unwrap(),
                        a.x,
                    )
                }
            },
            AlgorithmParameters::AlgorithmKeyPair(a) => {
                let alg = self
                    .common
                    .key_algorithm
                    .ok_or_else(|| new_error(ErrorKind::InvalidKeyFormat))?;
                // Members must appear in lexicographic order: alg, kty, pub.
                format!(
                    r#"{{"alg":{},"kty":{},"pub":"{}"}}"#,
                    serde_json::to_string(&alg).unwrap(),
                    serde_json::to_string(&a.key_type).unwrap(),
                    a.pub_,
                )
            }
            AlgorithmParameters::Other(_) => return Err(ErrorKind::UnsupportedAlgorithm.into()),
        };

        Ok(b64_encode((CryptoProvider::get_default().key_utils.compute_digest)(
            pre.as_bytes(),
            hash_function,
        )?))
    }
}

/// A JWK set
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[allow(missing_docs)]
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
    use std::collections::BTreeMap;

    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::Algorithm;
    use crate::algorithms::ML_DSA_44_PUBLIC_KEY_LEN;
    use crate::crypto::CryptoProvider;
    use crate::errors::ErrorKind;
    use crate::jwk::{
        AKPKeyParameters, AKPKeyType, AlgorithmParameters, CommonParameters, EllipticCurve, Jwk,
        JwkSet, KeyAlgorithm, OctetKeyPairParameters, OctetKeyPairType, OctetKeyType,
        RSAKeyParameters, ThumbprintHash,
    };
    use crate::serialization::b64_encode;
    use crate::{DecodingKey, EncodingKey};

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

    #[test]
    fn deserialize_unknown_key_algorithm() {
        let key_alg_json = json!("");
        let key_alg_result: KeyAlgorithm =
            serde_json::from_value(key_alg_json).expect("Could not deserialize json");
        assert_eq!(key_alg_result, KeyAlgorithm::UNKNOWN_ALGORITHM);
    }

    #[test]
    fn deserialize_unknown_kty() {
        let parameters_json = json!({
            "kty": "UKN",
            "foo": "bar",
            "solution": 42
        });
        let parameters_result: AlgorithmParameters =
            serde_json::from_value(parameters_json).expect("Could not deserialize json");
        match parameters_result {
            AlgorithmParameters::Other(other_key_parameters) => {
                let mut expected = BTreeMap::new();
                expected.insert("kty".to_owned(), serde_json::to_value("UKN").unwrap());
                expected.insert("foo".to_owned(), serde_json::to_value("bar").unwrap());
                expected.insert("solution".to_owned(), serde_json::to_value(42).unwrap());
                assert_eq!(other_key_parameters.fields, expected);
            }
            _ => {
                panic!("Unexpected deserialization result");
            }
        }
    }

    #[test]
    fn deserialize_public_akp_jwk_without_priv() {
        // A public AKP JWK omits the `priv` member entirely.
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "AKP",
            "alg": "ML-DSA-44",
            "pub": "abc",
        }))
        .expect("Could not deserialize json");

        // The top-level `alg` is shared with `common.key_algorithm`.
        assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::MLDSA44));

        match jwk.algorithm {
            AlgorithmParameters::AlgorithmKeyPair(params) => {
                assert_eq!(params.key_type, AKPKeyType::AKP);
                assert_eq!(params.pub_, "abc");
                assert!(params.priv_.is_none());
            }
            _ => panic!("Expected AlgorithmKeyPair"),
        }
    }

    #[test]
    fn akp_jwk_roundtrip_single_alg_member() {
        // Encode -> decode round-trip must preserve the AKP parameters and emit
        // exactly one `alg` member on the wire (RFC 9964).
        let input = json!({
            "kty": "AKP",
            "alg": "ML-DSA-44",
            "pub": "abc",
        });

        let jwk: Jwk = serde_json::from_value(input).expect("deserialize");
        let value = serde_json::to_value(&jwk).expect("serialize");

        let obj = value.as_object().expect("object");
        assert_eq!(obj.get("alg").and_then(|v| v.as_str()), Some("ML-DSA-44"));
        assert_eq!(obj.get("kty").and_then(|v| v.as_str()), Some("AKP"));
        assert_eq!(obj.get("pub").and_then(|v| v.as_str()), Some("abc"));
        // No duplicate/nested encoding of `alg`.
        assert_eq!(serde_json::to_string(&jwk).unwrap().matches("\"alg\"").count(), 1);
    }

    #[test]
    fn unknown_akp_alg_is_unsupported() {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "AKP",
            "alg": "future-signature-algorithm",
            "pub": "abc",
        }))
        .expect("deserialize");

        assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::UNKNOWN_ALGORITHM));
        assert!(matches!(jwk.algorithm, AlgorithmParameters::AlgorithmKeyPair(_)));
        assert!(!jwk.is_supported());
    }

    #[test]
    #[wasm_bindgen_test]
    fn check_thumbprint() {
        let tp = Jwk {
            common: crate::jwk::CommonParameters { key_id: Some("2011-04-29".to_string()), ..Default::default() },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: crate::jwk::RSAKeyType::RSA,
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string(),
                e: "AQAB".to_string(),
            }),
        }
        .thumbprint(ThumbprintHash::SHA256)
        .unwrap();

        assert_eq!(tp.as_str(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn check_thumbprint_bad_key() {
        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::ES256),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::P256,
                x: "".to_string(),
            }),
        };

        assert_eq!(
            jwk.thumbprint(ThumbprintHash::SHA256).unwrap_err().into_kind(),
            ErrorKind::InvalidKeyFormat
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn check_thumbprint_akp() {
        // RFC 9964 Section 6: the AKP thumbprint hashes the members
        // "alg", "kty", "pub" in lexicographic order.
        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::MLDSA44),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::AlgorithmKeyPair(AKPKeyParameters {
                key_type: AKPKeyType::AKP,
                priv_: None,
                pub_: "abc".to_string(),
            }),
        };

        let tp = jwk.thumbprint(ThumbprintHash::SHA256).unwrap();

        // Expected digest computed over the exact canonical JSON string,
        // locking both the member ordering and the wire-format of `alg`.
        let canonical = r#"{"alg":"ML-DSA-44","kty":"AKP","pub":"abc"}"#;
        let expected = b64_encode(
            (CryptoProvider::get_default().key_utils.compute_digest)(
                canonical.as_bytes(),
                ThumbprintHash::SHA256,
            )
            .unwrap(),
        );

        assert_eq!(tp, expected);
    }

    #[test]
    fn deserialize_akp_jwk_missing_alg_fails() {
        // RFC 9964 requires `alg` for AKP keys.
        let result: Result<Jwk, _> = serde_json::from_value(json!({
            "kty": "AKP",
            "pub": "abc",
        }));
        assert!(result.is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn check_alg_key_alg_conversion() {
        let pairs = [
            (Algorithm::HS256, KeyAlgorithm::HS256),
            (Algorithm::HS384, KeyAlgorithm::HS384),
            (Algorithm::HS512, KeyAlgorithm::HS512),
            (Algorithm::ES256, KeyAlgorithm::ES256),
            (Algorithm::ES384, KeyAlgorithm::ES384),
            (Algorithm::RS256, KeyAlgorithm::RS256),
            (Algorithm::RS384, KeyAlgorithm::RS384),
            (Algorithm::RS512, KeyAlgorithm::RS512),
            (Algorithm::PS256, KeyAlgorithm::PS256),
            (Algorithm::PS384, KeyAlgorithm::PS384),
            (Algorithm::PS512, KeyAlgorithm::PS512),
            (Algorithm::EdDSA, KeyAlgorithm::EdDSA),
            (Algorithm::MLDSA44, KeyAlgorithm::MLDSA44),
            (Algorithm::MLDSA65, KeyAlgorithm::MLDSA65),
            (Algorithm::MLDSA87, KeyAlgorithm::MLDSA87),
        ];

        for (alg, k_alg) in pairs {
            assert_eq!(KeyAlgorithm::from(alg), k_alg);
            assert_eq!(Algorithm::try_from(k_alg), Ok(alg));
        }

        assert!(
            Algorithm::try_from(KeyAlgorithm::RSA1_5)
                .is_err_and(|e| *e.kind() == ErrorKind::UnsupportedAlgorithm)
        );
        assert!(
            Algorithm::try_from(KeyAlgorithm::RSA_OAEP)
                .is_err_and(|e| *e.kind() == ErrorKind::UnsupportedAlgorithm)
        );
        assert!(
            Algorithm::try_from(KeyAlgorithm::RSA_OAEP_256)
                .is_err_and(|e| *e.kind() == ErrorKind::UnsupportedAlgorithm)
        );
    }

    #[test]
    #[cfg(feature = "use_pem")]
    fn check_jwk_from_decoding_key_rsa() {
        let enc_key =
            EncodingKey::from_rsa_pem(include_bytes!("../tests/rsa/private_rsa_key_pkcs8.pem"))
                .unwrap();
        let dec_key =
            DecodingKey::from_rsa_pem(include_bytes!("../tests/rsa/public_rsa_key_pkcs8.pem"))
                .unwrap();
        let expected_jwk = Jwk::from_encoding_key(&enc_key, Algorithm::RS256).unwrap();
        let jwk = Jwk::from_decoding_key(&dec_key, Some(Algorithm::RS256)).unwrap();
        assert_eq!(jwk, expected_jwk);
    }

    #[test]
    #[cfg(feature = "use_pem")]
    fn check_jwk_from_decoding_key_ec() {
        let enc_key =
            EncodingKey::from_ec_pem(include_bytes!("../tests/ecdsa/private_ecdsa_key.pem"))
                .unwrap();
        let dec_key =
            DecodingKey::from_ec_pem(include_bytes!("../tests/ecdsa/public_ecdsa_key.pem"))
                .unwrap();
        let expected_jwk = Jwk::from_encoding_key(&enc_key, Algorithm::ES256).unwrap();
        let jwk = Jwk::from_decoding_key(&dec_key, Some(Algorithm::ES256)).unwrap();
        assert_eq!(jwk, expected_jwk);
    }

    #[test]
    #[cfg(feature = "use_pem")]
    fn check_jwk_from_decoding_key_ed() {
        let enc_key =
            EncodingKey::from_ed_pem(include_bytes!("../tests/eddsa/private_ed25519_key.pem"))
                .unwrap();
        let dec_key =
            DecodingKey::from_ed_pem(include_bytes!("../tests/eddsa/public_ed25519_key.pem"))
                .unwrap();
        let expected_jwk = Jwk::from_encoding_key(&enc_key, Algorithm::EdDSA).unwrap();
        let jwk = Jwk::from_decoding_key(&dec_key, Some(Algorithm::EdDSA)).unwrap();
        assert_eq!(jwk, expected_jwk);
    }

    #[test]
    fn check_jwk_from_decoding_key_mldsa_validates_algorithm_and_size() {
        let dec_key = DecodingKey::from_mldsa_der(&[0; ML_DSA_44_PUBLIC_KEY_LEN]);

        assert!(Jwk::from_decoding_key(&dec_key, Some(Algorithm::MLDSA44)).is_ok());
        assert_eq!(
            Jwk::from_decoding_key(&dec_key, Some(Algorithm::HS256)).unwrap_err().into_kind(),
            ErrorKind::InvalidAlgorithm
        );
        assert_eq!(
            Jwk::from_decoding_key(&dec_key, Some(Algorithm::MLDSA65)).unwrap_err().into_kind(),
            ErrorKind::InvalidKeyFormat
        );
    }

    #[test]
    fn check_jwkset_default() {
        #[derive(Default)]
        struct Derived(JwkSet);

        assert!(Derived::default().0.keys.is_empty());
    }
}

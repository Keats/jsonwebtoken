use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind, Result};

/// Public-key lengths (in bytes) for the ML-DSA parameter sets, as fixed by
/// US NIST FIPS 204.
pub(crate) const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
pub(crate) const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
pub(crate) const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Supported families of algorithms.
pub enum AlgorithmFamily {
    /// HMAC shared secret family.
    Hmac,
    /// RSA-based public key family.
    Rsa,
    /// Elliptic curve public key family.
    Ec,
    /// Edwards curve public key family.
    Ed,
    /// ML-DSA public key family.
    Mldsa,
}

impl AlgorithmFamily {
    /// A list of all possible Algorithms that are part of the family.
    pub fn algorithms(&self) -> &[Algorithm] {
        match self {
            Self::Hmac => &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            Self::Rsa => &[
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
            ],
            Self::Ec => &[Algorithm::ES256, Algorithm::ES384],
            Self::Ed => &[Algorithm::EdDSA],
            Self::Mldsa => &[Algorithm::MLDSA44, Algorithm::MLDSA65, Algorithm::MLDSA87],
        }
    }
}

/// The algorithms supported for signing/verifying JWTs
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC using SHA-256
    #[default]
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

    /// ML-DSA-44 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-44")]
    MLDSA44,
    /// ML-DSA-65 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-65")]
    MLDSA65,
    /// ML-DSA-87 as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-87")]
    MLDSA87,
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "PS256" => Ok(Algorithm::PS256),
            "PS384" => Ok(Algorithm::PS384),
            "PS512" => Ok(Algorithm::PS512),
            "RS512" => Ok(Algorithm::RS512),
            "EdDSA" => Ok(Algorithm::EdDSA),
            "ML-DSA-44" => Ok(Algorithm::MLDSA44),
            "ML-DSA-65" => Ok(Algorithm::MLDSA65),
            "ML-DSA-87" => Ok(Algorithm::MLDSA87),
            _ => Err(ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::MLDSA44 => "ML-DSA-44",
            Algorithm::MLDSA65 => "ML-DSA-65",
            Algorithm::MLDSA87 => "ML-DSA-87",
        };
        f.write_str(s)
    }
}

impl Algorithm {
    /// The family of the algorithm.
    pub fn family(self) -> AlgorithmFamily {
        match self {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamily::Hmac,
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => AlgorithmFamily::Rsa,
            Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamily::Ec,
            Algorithm::EdDSA => AlgorithmFamily::Ed,
            Algorithm::MLDSA44 | Algorithm::MLDSA65 | Algorithm::MLDSA87 => AlgorithmFamily::Mldsa,
        }
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[test]
    #[wasm_bindgen_test]
    fn generate_algorithm_enum_from_str() {
        assert!(Algorithm::from_str("HS256").is_ok());
        assert!(Algorithm::from_str("HS384").is_ok());
        assert!(Algorithm::from_str("HS512").is_ok());
        assert!(Algorithm::from_str("RS256").is_ok());
        assert!(Algorithm::from_str("RS384").is_ok());
        assert!(Algorithm::from_str("RS512").is_ok());
        assert!(Algorithm::from_str("PS256").is_ok());
        assert!(Algorithm::from_str("PS384").is_ok());
        assert!(Algorithm::from_str("PS512").is_ok());
        assert!(Algorithm::from_str("EdDSA").is_ok());
        assert!(Algorithm::from_str("ML-DSA-44").is_ok());
        assert!(Algorithm::from_str("ML-DSA-65").is_ok());
        assert!(Algorithm::from_str("ML-DSA-87").is_ok());
        assert!(Algorithm::from_str("").is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn ml_dsa_wire_format_roundtrip() {
        // Locks the JWT `alg` header wire-format for ML-DSA variants
        // (RFC 9964 names use hyphens, not the Rust identifier spelling).
        let pairs = [
            (Algorithm::MLDSA44, "ML-DSA-44"),
            (Algorithm::MLDSA65, "ML-DSA-65"),
            (Algorithm::MLDSA87, "ML-DSA-87"),
        ];

        for (alg, wire) in pairs {
            // Serialize -> exact wire string.
            assert_eq!(serde_json::to_string(&alg).unwrap(), format!("\"{wire}\""));
            // Deserialize -> back to the same variant.
            assert_eq!(serde_json::from_str::<Algorithm>(&format!("\"{wire}\"")).unwrap(), alg);
            // FromStr round-trip.
            assert_eq!(Algorithm::from_str(wire).unwrap(), alg);
        }
    }
}

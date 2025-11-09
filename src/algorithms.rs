use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind, Result};

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum AlgorithmFamily {
    Hmac,

    #[cfg(feature = "rsa")]
    Rsa,
    Ec,
    Ed,
}

impl AlgorithmFamily {
    /// A list of all possible Algorithms that are part of the family.
    pub fn algorithms(&self) -> &[Algorithm] {
        match self {
            Self::Hmac => &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            #[cfg(feature = "rsa")]
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
        }
    }
}

/// The algorithms supported for signing/verifying JWTs
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
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

    #[cfg(feature = "rsa")]
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    #[cfg(feature = "rsa")]
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    #[cfg(feature = "rsa")]
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,

    #[cfg(feature = "rsa")]
    /// RSASSA-PSS using SHA-256
    PS256,
    #[cfg(feature = "rsa")]
    /// RSASSA-PSS using SHA-384
    PS384,
    #[cfg(feature = "rsa")]
    /// RSASSA-PSS using SHA-512
    PS512,

    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    EdDSA,
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
            #[cfg(feature = "rsa")]
            "RS256" => Ok(Algorithm::RS256),
            #[cfg(feature = "rsa")]
            "RS384" => Ok(Algorithm::RS384),
            #[cfg(feature = "rsa")]
            "PS256" => Ok(Algorithm::PS256),
            #[cfg(feature = "rsa")]
            "PS384" => Ok(Algorithm::PS384),
            #[cfg(feature = "rsa")]
            "PS512" => Ok(Algorithm::PS512),
            #[cfg(feature = "rsa")]
            "RS512" => Ok(Algorithm::RS512),
            "EdDSA" => Ok(Algorithm::EdDSA),
            _ => Err(ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl Algorithm {
    pub(crate) fn family(self) -> AlgorithmFamily {
        match self {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamily::Hmac,
            #[cfg(feature = "rsa")]
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => AlgorithmFamily::Rsa,
            Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamily::Ec,
            Algorithm::EdDSA => AlgorithmFamily::Ed,
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
        #[cfg(feature = "rsa")]
        {
            assert!(Algorithm::from_str("RS256").is_ok());
            assert!(Algorithm::from_str("RS384").is_ok());
            assert!(Algorithm::from_str("RS512").is_ok());
            assert!(Algorithm::from_str("PS256").is_ok());
            assert!(Algorithm::from_str("PS384").is_ok());
            assert!(Algorithm::from_str("PS512").is_ok());
        }
        assert!(Algorithm::from_str("").is_err());
    }
}

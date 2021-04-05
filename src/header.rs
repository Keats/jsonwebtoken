use serde::{Deserialize, Serialize};

use crate::algorithms::{Algorithm, AlgorithmFamily};
use crate::crypto::ecdsa::alg_to_ec_signing;
use crate::encoding::EncodingKey;
use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};

#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum JWK {
    EC {
        alg: String,
        crv: String,
        x: String,
        y: String,
    },
    RSA {
        alg: String,
        n: String,
        e: String,
    },
    #[serde(rename = "oct")]
    Oct {
        alg: String,
        k: String,
    },
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
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
    pub jwk: Option<JWK>,
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
            x5t: None,
        }
    }

    /// Converts an encoded part into the Header struct if possible
    pub(crate) fn from_encoded(encoded_part: &str) -> Result<Self> {
        let decoded = b64_decode(encoded_part)?;
        let s = String::from_utf8(decoded)?;

        Ok(serde_json::from_str(&s)?)
    }

    /// Build a JSON Web Key object and add it to the header
    pub fn add_jwk(&mut self, key: &EncodingKey) -> Result<()> {
        if key.family != self.alg.family() {
            return Err(new_error(ErrorKind::InvalidAlgorithm));
        }

        self.jwk = Some(match key.family {
            AlgorithmFamily::Hmac => {
                JWK::Oct { alg: self.alg.to_string(), k: b64_encode(&key.inner()) }
            }
            AlgorithmFamily::Ec => {
                let alg = alg_to_ec_signing(self.alg);
                let signing_key = EcdsaKeyPair::from_pkcs8(alg, &key.inner())?;
                let pub_key = signing_key.public_key().as_ref();

                if pub_key[0] != 0x04 || pub_key.len() != 65 {
                    // TODO
                    return Err(new_error(ErrorKind::InvalidAlgorithm));
                }

                JWK::EC {
                    alg: self.alg.to_string(),
                    crv: match self.alg {
                        Algorithm::ES256 => "P-256".to_string(),
                        Algorithm::ES384 => "P-384".to_string(),
                        _ => unreachable!(),
                    },
                    x: b64_encode(&pub_key[1..33]),
                    y: b64_encode(&pub_key[33..65]),
                }
            }
            AlgorithmFamily::Rsa => {
                let signing_key = RsaKeyPair::from_der(&key.inner())?;
                let pub_key = signing_key.public_key();

                JWK::RSA {
                    alg: self.alg.to_string(),
                    n: b64_encode(pub_key.modulus().big_endian_without_leading_zero()),
                    e: b64_encode(pub_key.exponent().big_endian_without_leading_zero()),
                }
            }
        });

        Ok(())
    }
}

impl Default for Header {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        Header::new(Algorithm::default())
    }
}

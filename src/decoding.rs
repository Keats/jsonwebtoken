use std::fmt::{Debug, Formatter};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::de::DeserializeOwned;

use crate::Algorithm;
use crate::algorithms::AlgorithmFamily;
use crate::crypto::JwtVerifier;
use crate::errors::{ErrorKind, Result, new_error};
use crate::header::{Alg, FromEncoded, Header};
use crate::jwk::{AlgorithmParameters, Jwk};
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{DecodedJwtPartClaims, b64_decode};
use crate::validation::{Validation, validate};
// Crypto
#[cfg(feature = "aws_lc_rs")]
use crate::crypto::aws_lc::{
    ecdsa::{Es256Verifier, Es384Verifier},
    eddsa::EdDSAVerifier,
    hmac::{Hs256Verifier, Hs384Verifier, Hs512Verifier},
    rsa::{
        Rsa256Verifier, Rsa384Verifier, Rsa512Verifier, RsaPss256Verifier, RsaPss384Verifier,
        RsaPss512Verifier,
    },
};
#[cfg(feature = "rust_crypto")]
use crate::crypto::rust_crypto::{
    ecdsa::{Es256Verifier, Es384Verifier},
    eddsa::EdDSAVerifier,
    hmac::{Hs256Verifier, Hs384Verifier, Hs512Verifier},
    rsa::{
        Rsa256Verifier, Rsa384Verifier, Rsa512Verifier, RsaPss256Verifier, RsaPss384Verifier,
        RsaPss512Verifier,
    },
};

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<H, T> {
    /// The decoded JWT header
    pub header: H,
    /// The decoded JWT claims
    pub claims: T,
}

impl<H, T> Clone for TokenData<H, T>
where
    H: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self { header: self.header.clone(), claims: self.claims.clone() }
    }
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

#[derive(Clone)]
pub(crate) enum DecodingKeyKind {
    SecretOrDer(Vec<u8>),
    RsaModulusExponent { n: Vec<u8>, e: Vec<u8> },
}

impl Debug for DecodingKeyKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecretOrDer(_) => f.debug_tuple("SecretOrDer").field(&"[redacted]").finish(),
            Self::RsaModulusExponent { .. } => f
                .debug_struct("RsaModulusExponent")
                .field("n", &"[redacted]")
                .field("e", &"[redacted]")
                .finish(),
        }
    }
}

/// All the different kind of keys we can use to decode a JWT.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone, Debug)]
pub struct DecodingKey {
    pub(crate) family: AlgorithmFamily,
    pub(crate) kind: DecodingKeyKind,
}

impl DecodingKey {
    /// The algorithm family this key is for.
    pub fn family(&self) -> AlgorithmFamily {
        self.family
    }

    /// If you're using HMAC, use this.
    pub fn from_secret(secret: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Hmac,
            kind: DecodingKeyKind::SecretOrDer(secret.to_vec()),
        }
    }

    /// If you're using HMAC with a base64 encoded secret, use this.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(DecodingKey { family: AlgorithmFamily::Hmac, kind: DecodingKeyKind::SecretOrDer(out) })
    }

    /// If you are loading a public RSA key in a PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you have (n, e) RSA public key components as strings, use this.
    pub fn from_rsa_components(modulus: &str, exponent: &str) -> Result<Self> {
        let n = b64_decode(modulus)?;
        let e = b64_decode(exponent)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::RsaModulusExponent { n, e },
        })
    }

    /// If you have (n, e) RSA public key components already decoded, use this.
    pub fn from_rsa_raw_components(modulus: &[u8], exponent: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::RsaModulusExponent { n: modulus.to_vec(), e: exponent.to_vec() },
        }
    }

    /// If you have a ECDSA public key in PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you have (x,y) ECDSA key components
    pub fn from_ec_components(x: &str, y: &str) -> Result<Self> {
        let x_cmp = b64_decode(x)?;
        let y_cmp = b64_decode(y)?;

        let mut public_key = Vec::with_capacity(1 + x.len() + y.len());
        public_key.push(0x04);
        public_key.extend_from_slice(&x_cmp);
        public_key.extend_from_slice(&y_cmp);

        Ok(DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(public_key),
        })
    }

    /// If you have a EdDSA public key in PEM format, use this.
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_public_key()?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(content.to_vec()),
        })
    }

    /// If you know what you're doing and have a RSA DER encoded public key, use this.
    pub fn from_rsa_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Rsa,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a RSA EC encoded public key, use this.
    pub fn from_ec_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ec,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// If you know what you're doing and have a Ed DER encoded public key, use this.
    pub fn from_ed_der(der: &[u8]) -> Self {
        DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(der.to_vec()),
        }
    }

    /// From x part (base64 encoded) of the JWK encoding
    pub fn from_ed_components(x: &str) -> Result<Self> {
        let x_decoded = b64_decode(x)?;
        Ok(DecodingKey {
            family: AlgorithmFamily::Ed,
            kind: DecodingKeyKind::SecretOrDer(x_decoded),
        })
    }

    /// If you have a key in Jwk format
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(params) => {
                DecodingKey::from_rsa_components(&params.n, &params.e)
            }
            AlgorithmParameters::EllipticCurve(params) => {
                DecodingKey::from_ec_components(&params.x, &params.y)
            }
            AlgorithmParameters::OctetKeyPair(params) => DecodingKey::from_ed_components(&params.x),
            AlgorithmParameters::OctetKey(params) => {
                let out = b64_decode(&params.value)?;
                Ok(DecodingKey {
                    family: AlgorithmFamily::Hmac,
                    kind: DecodingKeyKind::SecretOrDer(out),
                })
            }
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.kind {
            DecodingKeyKind::SecretOrDer(b) => b,
            DecodingKeyKind::RsaModulusExponent { .. } => unreachable!(),
        }
    }

    pub(crate) fn try_get_hmac_secret(&self) -> Result<&[u8]> {
        if self.family == AlgorithmFamily::Hmac {
            Ok(self.as_bytes())
        } else {
            Err(new_error(ErrorKind::InvalidKeyFormat))
        }
    }
}

impl TryFrom<&Jwk> for DecodingKey {
    type Error = crate::errors::Error;

    fn try_from(jwk: &Jwk) -> Result<Self> {
        Self::from_jwk(jwk)
    }
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned + Clone>(
    token: impl AsRef<[u8]>,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<Header, T>> {
    decode_with_custom_header(token, key, validation)
}

/// Decode and validate a JWT with a custom header
///
/// If the token or its signature is invalid, or the claims fail validation, this will return an
/// error.
pub fn decode_with_custom_header<H, T>(
    token: impl AsRef<[u8]>,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<H, T>>
where
    H: DeserializeOwned + Clone + FromEncoded + Alg,
    T: DeserializeOwned + Clone,
{
    let token = token.as_ref();

    let (signature, message) = expect_two!(token.rsplitn(2, |b| *b == b'.'));
    let (payload, header) = expect_two!(message.rsplitn(2, |b| *b == b'.'));
    let header = H::from_encoded(header)?;

    if validation.validate_signature && !validation.algorithms.contains(header.alg()) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let verifying_provider = jwt_verifier_factory(header.alg(), key)?;
    verify_signature_body(message, signature, &header, validation, verifying_provider)?;

    let decoded_claims = DecodedJwtPartClaims::from_jwt_part_claims(payload)?;
    validate(decoded_claims.deserialize()?, validation)?;

    let claims = decoded_claims.deserialize()?;

    Ok(TokenData { header, claims })
}

/// Decode a JWT with NO VALIDATION
///
/// DANGER: This performs zero validation on the JWT
pub fn insecure_decode<T: DeserializeOwned + Clone>(
    token: impl AsRef<[u8]>,
) -> Result<TokenData<T>> {
    let token = token.as_ref();

    let (_, message) = expect_two!(token.rsplitn(2, |b| *b == b'.'));
    let (payload, header) = expect_two!(message.rsplitn(2, |b| *b == b'.'));

    let header = Header::from_encoded(header)?;
    let claims = DecodedJwtPartClaims::from_jwt_part_claims(payload)?.deserialize()?;

    Ok(TokenData { header, claims })
}

/// Return the correct [`JwtVerifier`] based on the `algorithm`.
pub fn jwt_verifier_factory(
    algorithm: &Algorithm,
    key: &DecodingKey,
) -> Result<Box<dyn JwtVerifier>> {
    let jwt_encoder = match algorithm {
        Algorithm::HS256 => Box::new(Hs256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS384 => Box::new(Hs384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS512 => Box::new(Hs512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES256 => Box::new(Es256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES384 => Box::new(Es384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS256 => Box::new(Rsa256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS384 => Box::new(Rsa384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS512 => Box::new(Rsa512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS256 => Box::new(RsaPss256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS384 => Box::new(RsaPss384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS512 => Box::new(RsaPss512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::EdDSA => Box::new(EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
    };

    Ok(jwt_encoder)
}

/// Decode a JWT without any signature verification/validations and return its [Header](struct.Header.html).
///
/// If the token has an invalid format (ie 3 parts separated by a `.`), it will return an error.
///
/// ```rust
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: impl AsRef<[u8]>) -> Result<Header> {
    let token = token.as_ref();
    let (_, message) = expect_two!(token.rsplitn(2, |b| *b == b'.'));
    let (_, header) = expect_two!(message.rsplitn(2, |b| *b == b'.'));
    Header::from_encoded(header)
}

/// Decode only the custom header of a JWT without decoding or validating the payload
pub fn decode_custom_header<H>(token: impl AsRef<[u8]>) -> Result<H>
where
    H: DeserializeOwned + Clone + Alg + FromEncoded,
{
    let token = token.as_ref();
    let (_, message) = expect_two!(token.rsplitn(2, |b| *b == b'.'));
    let (_, header) = expect_two!(message.rsplitn(2, |b| *b == b'.'));
    H::from_encoded(header)
}

pub(crate) fn verify_signature_body(
    message: &[u8],
    signature: &[u8],
    header: &impl Alg,
    validation: &Validation,
    verifying_provider: Box<dyn JwtVerifier>,
) -> Result<()> {
    if validation.validate_signature && validation.algorithms.is_empty() {
        return Err(new_error(ErrorKind::MissingAlgorithm));
    }

    if validation.validate_signature {
        for alg in &validation.algorithms {
            if verifying_provider.algorithm().family() != alg.family() {
                return Err(new_error(ErrorKind::InvalidAlgorithm));
            }
        }
    }

    if validation.validate_signature && !validation.algorithms.contains(header.alg()) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    if validation.validate_signature
        && verifying_provider.verify(message, &b64_decode(signature)?).is_err()
    {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    Ok(())
}

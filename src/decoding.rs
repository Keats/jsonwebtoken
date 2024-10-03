use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::DeserializeOwned;

use crate::algorithms::AlgorithmFamily;
use crate::crypto::hmac::{HmacSecret, Hs256, Hs384, Hs512};
use crate::crypto::JwtVerifier;
use crate::errors::{new_error, Error, ErrorKind, Result};
use crate::header::Header;
use crate::jwk::{AlgorithmParameters, Jwk};
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_decode, DecodedJwtPartClaims};
use crate::validation::{validate, Validation};
use crate::Algorithm;

/// The return type of a successful call to [decode](fn.decode.html).
#[derive(Debug)]
pub struct TokenData<T> {
    /// The decoded JWT header
    pub header: Header,
    /// The decoded JWT claims
    pub claims: T,
}

impl<T> Clone for TokenData<T>
where
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

/// All the different kind of keys we can use to decode a JWT.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct DecodingKey {
    pub(crate) family: AlgorithmFamily,
    pub(crate) kind: DecodingKeyKind,
}

impl DecodingKey {
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
}

/// Decode and validate a JWT
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>> {
    // The decoding step is unfortunately a little clunky but that seems to be how I need to do it to fit it into the `decode` function
    let header = decode_header(token)?;

    if validation.validate_signature && !(validation.algorithms.contains(&header.alg)) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let decoder = decoder_factory(&header.alg, key)?.with_validation(validation)?;

    decoder.decode(token)
}

/// Return the correct decoder based on the `algorithm`.
fn decoder_factory(algorithm: &Algorithm, key: &DecodingKey) -> Result<JwtDecoder> {
    let jwt_encoder = match algorithm {
        Algorithm::HS256 => JwtDecoder::hs_256(key.try_into()?)?,
        Algorithm::HS384 => JwtDecoder::hs_384(key.try_into()?)?,
        Algorithm::HS512 => JwtDecoder::hs_512(key.try_into()?)?,
        Algorithm::ES256 => todo!(),
        Algorithm::ES384 => todo!(),
        Algorithm::RS256 => todo!(),
        Algorithm::RS384 => todo!(),
        Algorithm::RS512 => todo!(),
        Algorithm::PS256 => todo!(),
        Algorithm::PS384 => todo!(),
        Algorithm::PS512 => todo!(),
        Algorithm::EdDSA => todo!(),
    };

    Ok(jwt_encoder)
}

/// Convert a [`&DecodingKey`] into an [`HmacSecret`]
impl TryInto<HmacSecret> for &DecodingKey {
    type Error = Error;

    fn try_into(self) -> std::result::Result<HmacSecret, Self::Error> {
        match self.kind.clone() {
            DecodingKeyKind::SecretOrDer(vec) => Ok(HmacSecret::from_secret(&vec)),
            DecodingKeyKind::RsaModulusExponent { .. } => {
                Err(new_error(crate::errors::ErrorKind::InvalidKeyFormat))
            }
        }
    }
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
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, message) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(message.rsplitn(2, '.'));
    Header::from_encoded(header)
}

/// A builder style JWT decoder
///
/// # Examples
///
/// ```
/// use jsonwebtoken::{JwtDecoder, HmacSecret};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String,
///    exp: usize,
/// }
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
///
/// let hmac_secret = HmacSecret::from_secret(b"secret");
///
/// let claims = JwtDecoder::hs_256(hmac_secret)
///     .unwrap()
///     .decode::<Claims>(&token)
///     .unwrap();
/// ```
pub struct JwtDecoder {
    verifying_provider: Box<dyn JwtVerifier>,
    validation: Validation,
}

impl JwtDecoder {
    /// Create a new [`JwtDecoder`] with any `verifying_provider` that implements the [`JwtVerifier`] trait.
    pub fn from_verifier<V: JwtVerifier + 'static>(verifying_provider: V) -> Self {
        Self::from_boxed_verifiyer(Box::new(verifying_provider))
    }

    /// Create a new [`JwtDecoder`] with any `verifying_provider` implements the [`JwtVerifier`] trait.
    pub fn from_boxed_verifiyer(verifying_provider: Box<dyn JwtVerifier>) -> Self {
        let validation = Validation::new(verifying_provider.algorithm());

        Self { verifying_provider, validation }
    }

    /// Provide custom a custom validation configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use jsonwebtoken::{JwtDecoder, HmacSecret, Validation, Algorithm};
    ///
    /// let hmac_secret = HmacSecret::from_secret(b"secret");
    /// let mut validation = Validation::new(Algorithm::HS256);
    /// validation.leeway = 5;
    ///
    /// let jwt_decoder = JwtDecoder::hs_256(hmac_secret)
    ///     .unwrap()
    ///     .with_validation(&validation)
    ///     .unwrap();
    /// ```
    pub fn with_validation(mut self, validation: &Validation) -> Result<Self> {
        // Check that the validation contains the correct algorithm
        if validation.validate_signature
            && !validation.algorithms.contains(&self.verifying_provider.algorithm())
        {
            return Err(new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }

        self.validation = validation.clone();
        Ok(self)
    }

    /// Decode and verify a JWT `token` using the `verifying_provider` and `validation` of the [`JwtDecoder`]
    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<TokenData<T>> {
        let (header, claims) = self.verify_signature(token)?;

        let decoded_claims = DecodedJwtPartClaims::from_jwt_part_claims(claims)?;
        let claims = decoded_claims.deserialize()?;
        validate(decoded_claims.deserialize()?, &self.validation)?;

        Ok(TokenData { header, claims })
    }

    /// Verify signature of a JWT, and return header object and raw payload
    ///
    /// If the token or its signature is invalid, it will return an error.
    fn verify_signature<'a>(&self, token: &'a str) -> Result<(Header, &'a str)> {
        if self.validation.validate_signature && self.validation.algorithms.is_empty() {
            return Err(new_error(ErrorKind::MissingAlgorithm));
        }

        // Todo: This behaviour is currently not captured anywhere.
        // if validation.validate_signature {
        //     for alg in &validation.algorithms {
        //         if key.family != alg.family() {
        //             return Err(new_error(ErrorKind::InvalidAlgorithm));
        //         }
        //     }
        // }

        let (signature, message) = expect_two!(token.rsplitn(2, '.'));
        let (payload, header) = expect_two!(message.rsplitn(2, '.'));
        let header = Header::from_encoded(header)?;

        if self.validation.validate_signature && !self.validation.algorithms.contains(&header.alg) {
            return Err(new_error(ErrorKind::InvalidAlgorithm));
        }

        if self.validation.validate_signature
            && self.verifying_provider.verify(message.as_bytes(), &b64_decode(signature)?).is_err()
        {
            return Err(new_error(ErrorKind::InvalidSignature));
        }

        Ok((header, payload))
    }

    /// Create new [`JwtDecoder`] with the `HS256` algorithm.
    pub fn hs_256(secret: HmacSecret) -> Result<JwtDecoder> {
        let verifying_provider = Box::new(Hs256::new(secret)?);

        Ok(JwtDecoder::from_boxed_verifiyer(verifying_provider))
    }

    /// Create new [`JwtDecoder`] with the `HS384` algorithm.
    pub fn hs_384(secret: HmacSecret) -> Result<JwtDecoder> {
        let verifying_provider = Box::new(Hs384::new(secret)?);

        Ok(JwtDecoder::from_boxed_verifiyer(verifying_provider))
    }

    /// Create new [`JwtDecoder`] with the `HS512` algorithm.
    pub fn hs_512(secret: HmacSecret) -> Result<JwtDecoder> {
        let verifying_provider = Box::new(Hs512::new(secret)?);

        Ok(JwtDecoder::from_boxed_verifiyer(verifying_provider))
    }
}

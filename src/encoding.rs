use base64::{engine::general_purpose::STANDARD, Engine};
use serde::ser::Serialize;

use crate::algorithms::AlgorithmFamily;
use crate::crypto::hmac::{HmacSecret, Hs256, Hs384};
use crate::crypto::JwtSigner;
use crate::errors::{new_error, ErrorKind, Result};
use crate::header::Header;
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_encode, b64_encode_part};
use crate::Algorithm;

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone)]
pub struct EncodingKey {
    pub(crate) family: AlgorithmFamily,
    content: Vec<u8>,
}

impl EncodingKey {
    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Hmac, content: secret.to_vec() }
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        Ok(EncodingKey { family: AlgorithmFamily::Hmac, content: out })
    }

    /// If you are loading a RSA key from a .pem file.
    /// This errors if the key is not a valid RSA key.
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// According to the [ring doc](https://docs.rs/ring/latest/ring/signature/struct.RsaKeyPair.html#method.from_pkcs8),
    /// the key should be at least 2047 bits.
    ///
    #[cfg(feature = "use_pem")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Rsa, content: content.to_vec() })
    }

    /// If you are loading a ECDSA key from a .pem file
    /// This errors if the key is not a valid private EC key
    /// Only exists if the feature `use_pem` is enabled.
    ///
    /// # NOTE
    ///
    /// The key should be in PKCS#8 form.
    ///
    /// You can generate a key with the following:
    ///
    /// ```sh
    /// openssl ecparam -genkey -noout -name prime256v1 \
    ///     | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
    /// ```
    #[cfg(feature = "use_pem")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ec, content: content.to_vec() })
    }

    /// If you are loading a EdDSA key from a .pem file
    /// This errors if the key is not a valid private Ed key
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_private_key()?;
        Ok(EncodingKey { family: AlgorithmFamily::Ed, content: content.to_vec() })
    }

    /// If you know what you're doing and have the DER-encoded key, for RSA only
    pub fn from_rsa_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Rsa, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for ECDSA
    pub fn from_ec_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ec, content: der.to_vec() }
    }

    /// If you know what you're doing and have the DER-encoded key, for EdDSA
    pub fn from_ed_der(der: &[u8]) -> Self {
        EncodingKey { family: AlgorithmFamily::Ed, content: der.to_vec() }
    }

    pub(crate) fn inner(&self) -> &[u8] {
        &self.content
    }
}

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key.
/// If the algorithm given is RSA or EC, the key needs to be in the PEM format.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{encode, Algorithm, Header, EncodingKey};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &EncodingKey) -> Result<String> {
    if key.family != header.alg.family() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let jwt_encoder = encoder_factory(&header.alg, key)?.with_header(header)?;

    jwt_encoder.encode(claims)
}

fn encoder_factory(algorithm: &Algorithm, key: &EncodingKey) -> Result<JwtEncoder> {
    let jwt_encoder = match algorithm {
        // Todo: Need to implement `TryInto<HmacSecret> for &EncodingKey`
        Algorithm::HS256 => JwtEncoder::hs_256(HmacSecret::from_secret(&key.content))?,
        Algorithm::HS384 => JwtEncoder::hs_384(HmacSecret::from_secret(&key.content))?,
        Algorithm::HS512 => todo!(),
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

/// # Todo
///
/// - Documentation
pub struct JwtEncoder {
    signing_provider: Box<dyn JwtSigner>,
    header: Header,
}

impl JwtEncoder {
    /// Todo
    pub fn from_signer<S: JwtSigner + 'static>(signing_provider: S) -> Self {
        Self::from_boxed_signer(Box::new(signing_provider))
    }

    /// Create a new [`JwtEncoder`] with any crypto provider that implements the [`CryptoProvider`] trait.
    pub fn from_boxed_signer(signing_provider: Box<dyn JwtSigner>) -> Self {
        // Determine a default header
        let mut header = Header::new(signing_provider.algorithm());
        header.typ = Some("JWT".to_owned());

        Self { signing_provider, header }
    }

    /// Provide a custom header.
    ///
    /// This would be used in the rare cases that fields other than `algorithm` and `type` need to be populated.
    ///
    /// # Todo
    ///
    /// - Test the the error checking works
    pub fn with_header(mut self, header: &Header) -> Result<Self> {
        // Check that the header makes use of the correct algorithm
        if header.alg != self.signing_provider.algorithm() {
            return Err(new_error(crate::errors::ErrorKind::InvalidAlgorithm));
        }

        self.header = header.clone();
        Ok(self)
    }

    /// Encode and sign the `claims` as a JWT.
    ///
    /// # Todo
    ///
    /// - Put in example usage.
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        let encoded_header = b64_encode_part(&self.header)?;
        let encoded_claims = b64_encode_part(claims)?;
        let message = [encoded_header, encoded_claims].join(".");

        let signature = b64_encode(&self.signing_provider.sign(message.as_bytes()));

        Ok([message, signature].join("."))
    }

    /// Create new [`JwtEncoder`] with the `HS256` algorithm.
    pub fn hs_256(secret: HmacSecret) -> Result<JwtEncoder> {
        let signing_provider = Box::new(Hs256::new(secret)?);

        Ok(JwtEncoder::from_boxed_signer(signing_provider))
    }

    /// Create new [`JwtEncoder`] with the `HS384` algorithm.
    pub fn hs_384(secret: HmacSecret) -> Result<JwtEncoder> {
        let signing_provider = Box::new(Hs384::new(secret)?);

        Ok(JwtEncoder::from_boxed_signer(signing_provider))
    }
}

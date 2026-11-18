use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, OnceLock};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use serde::ser::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algorithms::{Algorithm, AlgorithmFamily};
use crate::crypto::CryptoProvider;
use crate::errors::{ErrorKind, Result, new_error};
use crate::header::Header;
#[cfg(feature = "use_pem")]
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::{b64_encode, b64_encode_part};

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance.
#[derive(Clone, ZeroizeOnDrop)]
pub struct EncodingKey {
    #[zeroize(skip)]
    family: AlgorithmFamily,
    content: Vec<u8>,
    /// The key as parsed by the crypto backend, so it isn't parsed again on every sign.
    #[zeroize(skip)]
    parsed: OnceLock<(Algorithm, Arc<dyn Any + Send + Sync>)>,
}

impl Zeroize for EncodingKey {
    fn zeroize(&mut self) {
        self.content.zeroize();
        // Drop the parsed key too, otherwise a zeroized key could still sign.
        self.parsed = OnceLock::new();
    }
}

impl EncodingKey {
    fn new(family: AlgorithmFamily, content: Vec<u8>) -> Self {
        EncodingKey { family, content, parsed: OnceLock::new() }
    }

    /// Returns the key parsed by `parse`, reusing the result of the first call made with `alg`.
    pub(crate) fn parsed<T: Any + Send + Sync>(
        &self,
        alg: Algorithm,
        parse: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<Arc<T>> {
        if let Some((cached_alg, key)) = self.parsed.get()
            && *cached_alg == alg
            && let Ok(key) = key.clone().downcast::<T>()
        {
            return Ok(key);
        }
        let key = Arc::new(parse(&self.content)?);
        let _ = self.parsed.set((alg, key.clone()));
        Ok(key)
    }

    /// The algorithm family this key is for.
    pub fn family(&self) -> AlgorithmFamily {
        self.family
    }

    /// If you're using a HMAC secret that is not base64, use that.
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        if secret.is_empty() {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        Ok(EncodingKey::new(AlgorithmFamily::Hmac, secret.to_vec()))
    }

    /// If you have a base64 HMAC secret, use that.
    pub fn from_base64_secret(secret: &str) -> Result<Self> {
        let out = STANDARD.decode(secret)?;
        if out.is_empty() {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        Ok(EncodingKey::new(AlgorithmFamily::Hmac, out))
    }

    /// For loading websafe base64 HMAC secrets, ex: ACME EAB credentials.
    pub fn from_urlsafe_base64_secret(secret: &str) -> Result<Self> {
        let out = URL_SAFE.decode(secret)?;
        if out.is_empty() {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        Ok(EncodingKey::new(AlgorithmFamily::Hmac, out))
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
        Ok(EncodingKey::new(AlgorithmFamily::Rsa, content.to_vec()))
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
        Ok(EncodingKey::new(AlgorithmFamily::Ec, content.to_vec()))
    }

    /// If you are loading a EdDSA key from a .pem file
    /// This errors if the key is not a valid private Ed key
    /// Only exists if the feature `use_pem` is enabled.
    #[cfg(feature = "use_pem")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ed_private_key()?;
        Ok(EncodingKey::new(AlgorithmFamily::Ed, content.to_vec()))
    }

    /// If you know what you're doing and have the DER-encoded key, for RSA only
    pub fn from_rsa_der(der: &[u8]) -> Self {
        EncodingKey::new(AlgorithmFamily::Rsa, der.to_vec())
    }

    /// If you know what you're doing and have the DER-encoded key, for ECDSA
    pub fn from_ec_der(der: &[u8]) -> Self {
        EncodingKey::new(AlgorithmFamily::Ec, der.to_vec())
    }

    /// If you know what you're doing and have the DER-encoded key, for EdDSA
    pub fn from_ed_der(der: &[u8]) -> Self {
        EncodingKey::new(AlgorithmFamily::Ed, der.to_vec())
    }

    /// Get the value of the key.
    ///
    /// To be used for defining your own `CryptoProvider`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }
}

impl Debug for EncodingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodingKey")
            .field("family", &self.family)
            .field("content", &"[redacted]")
            .finish()
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
/// let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref()).unwrap()).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &EncodingKey) -> Result<String> {
    if key.family != header.alg.family() {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let signing_provider = (CryptoProvider::get_default().signer_factory)(&header.alg, key)?;

    if signing_provider.algorithm() != header.alg {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(claims)?;
    let message = [encoded_header, encoded_claims].join(".");

    let signature = b64_encode(signing_provider.try_sign(message.as_bytes())?);

    Ok([message, signature].join("."))
}

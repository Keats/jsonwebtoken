use serde::ser::Serialize;

use crate::crypto;
use crate::errors::Result;
use crate::header::Header;
use crate::pem::decoder::PemEncodedKey;
use crate::serialization::b64_encode_part;

/// A key to encode a JWT with. Can be a secret, a PEM-encoded key or a DER-encoded key.
/// This key can be re-used so make sure you only initialize it once if you can for better performance
#[derive(Debug, Clone, PartialEq)]
pub struct EncodingKey {
    content: Vec<u8>,
}

impl EncodingKey {
    /// If you're using HMAC, use that.
    pub fn from_secret(secret: &[u8]) -> Self {
        EncodingKey { content: secret.to_vec() }
    }

    /// If you are loading a RSA key from a .pem file.
    /// This errors if the key is not a valid RSA key.
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_rsa_key()?;
        Ok(EncodingKey { content: content.to_vec() })
    }

    /// If you are loading a ECDSA key from a .pem file
    /// This errors if the key is not a valid private EC key
    pub fn from_ec_pem(key: &[u8]) -> Result<Self> {
        let pem_key = PemEncodedKey::new(key)?;
        let content = pem_key.as_ec_private_key()?;
        Ok(EncodingKey { content: content.to_vec() })
    }

    /// If you know what you're doing and have the DER-encoded key, for RSA or ECDSA
    pub fn from_der(der: &[u8]) -> Self {
        EncodingKey { content: der.to_vec() }
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
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = crypto::sign(&*message, key, header.alg)?;

    Ok([message, signature].join("."))
}

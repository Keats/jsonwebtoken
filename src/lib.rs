//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod header;
mod pem;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
pub use decoding::{
    dangerous_unsafe_decode, decode, decode_header, decode_rsa_components, TokenData,
};
pub use header::Header;
pub use validation::Validation;

use serde::ser::Serialize;

use crate::errors::Result;
use crate::serialization::b64_encode_part;

/// Encode the header and claims given and sign the payload using the algorithm from the header and the key.
/// If the algorithm given is RSA or EC, the key needs to be in the PEM format.
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use jsonwebtoken::{encode, Algorithm, Header};
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
/// let token = encode(&Header::default(), &my_claims, "secret".as_ref()).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &[u8]) -> Result<String> {
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = crypto::sign(&*message, key, header.alg)?;

    Ok([message, signature].join("."))
}

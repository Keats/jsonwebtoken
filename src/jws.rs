//! JSON Web Signatures data type.
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// This is a serde-compatible JSON Web Signature structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jws<C> {
    /// The base64 encoded header data.
    ///
    /// Defined in [RFC7515#3.2](https://tools.ietf.org/html/rfc7515#section-3.2).
    pub protected: String,
    /// The base64 encoded claims data.
    ///
    /// Defined in [RFC7515#3.2](https://tools.ietf.org/html/rfc7515#section-3.2).
    pub payload: String,
    /// The signature on the other fields.
    ///
    /// Defined in [RFC7515#3.2](https://tools.ietf.org/html/rfc7515#section-3.2).
    pub signature: String,
    /// Unused, for associating type metadata.
    #[serde(skip)]
    pub _pd: PhantomData<C>,
}

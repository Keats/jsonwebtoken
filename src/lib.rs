//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken)
//!

#![deny(missing_docs)]

pub use algorithms::Algorithm;
pub use decoding::{DecodingKey, TokenData, decode, decode_header};
pub use encoding::{EncodingKey, encode};
pub use header::Header;
pub use validation::{Validation, get_current_timestamp};

/// Things needed to implement a custom crypto provider.
#[cfg(feature = "custom-provider")]
pub mod custom_provider {
    pub use crate::algorithms::AlgorithmFamily;
    pub use signature::{Error, Signer, Verifier};
}

/// Dangerous decoding functions that should be audited and used with extreme care.
pub mod dangerous {
    pub use super::decoding::insecure_decode;
}

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod header;
pub mod jwk;
pub mod jws;
#[cfg(feature = "use_pem")]
mod pem;
mod serialization;
mod validation;

//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
compile_error!(
    "feature \"rust_crypto\" and feature \"aws_lc_rs\" cannot be enabled at the same time"
);

#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
compile_error!("at least one of the features \"rust_crypto\" or \"aws_lc_rs\" must be enabled");

pub use algorithms::Algorithm;
pub use decoding::{DecodingKey, TokenData, decode, decode_header};
pub use encoding::{EncodingKey, encode};
pub use header::Header;
pub use validation::{Validation, get_current_timestamp};

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

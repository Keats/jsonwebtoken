//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
compile_error!(
    "feature \"rust_crypto\" and feature \"aws_lc_rs\" cannot be enabled at the same time"
);

pub use algorithms::Algorithm;
pub use crypto::hmac::HmacSecret;
pub use decoding::{decode, decode_header, DecodingKey, TokenData, _decode};
pub use encoding::{encode, EncodingKey, _encode};
pub use header::Header;
pub use validation::{get_current_timestamp, Validation};

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod header;
pub mod jwk;
#[cfg(feature = "use_pem")]
mod pem;
mod serialization;
mod validation;

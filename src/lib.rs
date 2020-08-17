//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![deny(missing_docs)]

mod algorithms;
/// Lower level functions, if you want to do something other than JWTs
pub mod crypto;
mod decoding;
mod encoding;
/// All the errors that can be encountered while encoding/decoding JWTs
pub mod errors;
mod header;
mod pem;
mod serialization;
mod validation;

pub use algorithms::Algorithm;
#[allow(deprecated)]
pub use decoding::dangerous_unsafe_decode;
pub use decoding::{
    dangerous_insecure_decode, dangerous_insecure_decode_with_validation, decode, decode_header,
    DecodingKey, TokenData,
};
pub use encoding::{encode, EncodingKey};
pub use header::Header;
pub use validation::Validation;

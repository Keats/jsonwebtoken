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
pub use decoding::{
    dangerous_unsafe_decode, decode, decode_header, decode_rsa_components, TokenData,
};
pub use encoding::{encode, EncodingKey};
pub use header::Header;
pub use validation::Validation;

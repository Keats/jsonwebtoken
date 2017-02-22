//! Create and parses JWT (JSON Web Tokens)
//!
#![recursion_limit = "300"]


#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
extern crate base64;
extern crate ring;
extern crate untrusted;

pub mod errors;
mod header;
mod crypto;
mod serialization;

pub use header::{Header};
pub use crypto::{
    Algorithm,
    sign,
    verify,
    encode,
    decode,
    decode_without_verification,
};


//! Create and parses JWT (JSON Web Tokens)
//!

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
extern crate base64;
extern crate ring;

pub mod errors;
mod header;
mod crypto;

pub use header::{Header};
pub use crypto::{Algorithm, sign, verify, encode, decode};


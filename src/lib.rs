//! Create and parses JWT (JSON Web Tokens)
//!

// #![deny(
//     missing_docs,
//     missing_debug_implementations, missing_copy_implementations,
//     trivial_casts, trivial_numeric_casts,
//     unsafe_code,
//     unstable_features,
//     unused_import_braces, unused_qualifications
// )]

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate rustc_serialize;

pub mod errors;
pub mod header;
pub mod claims;

#[derive(Debug)]
pub enum Algorithm {
    HS256
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match *self {
            Algorithm::HS256 => "HS256".to_owned(),
        }
    }
}

// pub fn encode(secret: String, algorithm: Algorithm) -> String {

// }

// pub fn decode(token: String, secret: String, algorithm: Algorithm) -> Result<int> {

// }

#[cfg(test)]
mod tests {
}

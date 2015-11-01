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

#![feature(test)]
extern crate rustc_serialize;
extern crate crypto;
extern crate test;

use rustc_serialize::{json, Encodable, Decodable};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;

pub mod errors;
use errors::Error;

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

// A part of the JWT: header, claims and signature
pub trait Part {
    fn from_base64(encoded: String) -> Result<Self, Error> where Self: Sized;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T> Part for T where T: Encodable + Decodable {
    fn to_base64(&self) -> Result<String, Error> {
        let encoded = try!(json::encode(&self));
        Ok(encoded.as_bytes().to_base64(base64::STANDARD))
    }

    fn from_base64(encoded: String) -> Result<T, Error> {
        let decoded = try!(encoded.as_bytes().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(json::decode(&s)))
    }
}

#[derive(Debug, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Header {
    typ: String,
    alg: String,
}

impl Header {
    pub fn new(algorithm: String) -> Header {
        Header {
            typ: "JWT".to_owned(),
            alg: algorithm,
        }
    }
}

fn sign(data: &str, secret: &[u8], algorithm: Algorithm) -> String {
    let digest = match algorithm {
        Algorithm::HS256 => Sha256::new(),
    };
    let mut hmac = Hmac::new(digest, secret);
    hmac.input(data.as_bytes());
    hmac.result().code().to_base64(base64::STANDARD)
}

pub fn encode<T: Part>(claims: T, secret: String, algorithm: Algorithm) -> Result<String, Error> {
    let encoded_header = try!(Header::new(algorithm.to_string()).to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let first_part = [encoded_header, encoded_claims].join(".");
    Ok("hey".to_owned())
}

// pub fn decode(token: String, secret: String, algorithm: Algorithm) -> Result<int> {

// }

#[cfg(test)]
mod tests {
    use super::{encode, Algorithm, Header, Part, sign};
    use test::Bencher;

    #[test]
    fn to_base64() {
        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".to_owned();
        let result = Header::new("HS256".to_owned()).to_base64();

        assert_eq!(expected, result.unwrap());
    }

    #[test]
    fn from_base64() {
        let encoded = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".to_owned();
        let header = Header::from_base64(encoded).unwrap();

        assert_eq!(header.typ, "JWT");
        assert_eq!(header.alg, "HS256");
    }

    #[test]
    fn round_trip() {
        let header = Header::new("HS256".to_owned());
        assert_eq!(Header::from_base64(header.to_base64().unwrap()).unwrap(), header);
    }

    #[test]
    fn sign_hs256() {
        let result = sign("hello world", "secret".as_bytes(), Algorithm::HS256);
        let expected = "NzM0Y2M2MmYzMjg0MTU2OGY0NTcxNWFlYjlmNGQ3ODkxMzI0ZTZkOTQ4ZTRjNmM2MGMwNjIxY2RhYzQ4NjIzYQ==";
        assert_eq!(result, expected);
    }

    // #[test]
    // fn encode_token() {
    //     #[derive(Debug, RustcEncodable, RustcDecodable)]
    //     struct Claims {
    //         sub: String,
    //         company: String
    //     }
    //     let my_claims = Claims {
    //         sub: "b@b.com".to_owned(),
    //         company: "ACME".to_owned()
    //     };
    //     let token = encode::<Claims>(my_claims, "secret".to_owned(), Algorithm::HS256);

    //     assert_eq!(token.unwrap(), "HS256");
    // }
}

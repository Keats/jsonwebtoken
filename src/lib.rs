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
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
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
    hmac.result().code().to_base64(base64::URL_SAFE)
}

fn verify(signature: &str, data: &str, secret: &[u8], algorithm: Algorithm) -> bool {
    let result = sign(data, secret, algorithm);
    signature == result
}

pub fn encode<T: Part>(claims: T, secret: String, algorithm: Algorithm) -> Result<String, Error> {
    let encoded_header = try!(Header::new(algorithm.to_string()).to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header, encoded_claims].join(".");
    let signature = sign(&*payload, secret.as_bytes(), algorithm);

    Ok([payload, signature].join("."))
}

pub fn decode<T: Part>(token: String, secret: String, algorithm: Algorithm) -> Result<T, Error> {
    let parts: Vec<&str> = token.split(".").collect();
    if parts.len() != 3 {
        return Err(Error::InvalidToken);
    }

    let is_valid = verify(
        parts[2],
        &[parts[0], parts[1]].join("."),
        secret.as_bytes(),
        algorithm
    );

    if !is_valid {
        return Err(Error::InvalidSignature);
    }

    // let header = try!(Header::from_base64(parts[0].to_owned()));
    let claims: T = try!(T::from_base64(parts[1].to_owned()));
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::{encode, decode, Algorithm, Header, Part, sign, verify};
    use test::Bencher;

    #[derive(Debug, PartialEq, Clone, RustcEncodable, RustcDecodable)]
    struct Claims {
        sub: String,
        company: String
    }

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
    fn round_trip_base64() {
        let header = Header::new("HS256".to_owned());
        assert_eq!(Header::from_base64(header.to_base64().unwrap()).unwrap(), header);
    }

    #[test]
    fn sign_hs256() {
        let result = sign("hello world", "secret".as_bytes(), Algorithm::HS256);
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        assert_eq!(result, expected);
    }

    #[test]
    fn verify_hs256() {
        let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let result = verify(sig.into(), "hello world", "secret".as_bytes(), Algorithm::HS256);
        assert!(result == true);
    }

    #[test]
    fn round_trip_claim() {
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let token = encode::<Claims>(my_claims.clone(), "secret".to_owned(), Algorithm::HS256).unwrap();
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256).unwrap();
        assert_eq!(my_claims, claims);
    }

    #[test]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
        assert_eq!(claims.is_ok(), false);
    }

    #[test]
    fn decode_token_invalid_signature() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
        assert_eq!(claims.is_ok(), false);
    }

    #[bench]
    fn bench_encode(b: &mut Bencher) {
        b.iter(|| encode::<Claims>(
            Claims {
                sub: "b@b.com".to_owned(),
                company: "ACME".to_owned()
            },
            "secret".to_owned(),
            Algorithm::HS256
        ));
    }

    #[bench]
    fn bench_decode(b: &mut Bencher) {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ".to_owned();
        b.iter(|| decode::<Claims>(
            token.clone(),
            "secret".to_owned(),
            Algorithm::HS256
        ));
    }
}

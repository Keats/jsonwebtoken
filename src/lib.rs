//! Create and parses JWT (JSON Web Tokens)
//!

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

extern crate rustc_serialize;
extern crate crypto;

use rustc_serialize::{json, Encodable, Decodable};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use crypto::sha2::{Sha256, Sha384, Sha512};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;

pub mod errors;
use errors::Error;

#[derive(Debug, PartialEq, Copy, Clone, RustcDecodable, RustcEncodable)]
/// The algorithms supported for signing/verifying
pub enum Algorithm {
    HS256,
    HS384,
    HS512
}

/// A part of the JWT: header and claims specifically
/// Allows converting from/to struct with base64
pub trait Part {
    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<Self, Error> where Self: Sized;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T> Part for T where T: Encodable + Decodable {
    fn to_base64(&self) -> Result<String, Error> {
        let encoded = try!(json::encode(&self));
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<T, Error> {
        let decoded = try!(encoded.as_ref().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(json::decode(&s)))
    }
}

#[derive(Debug, PartialEq, RustcEncodable, RustcDecodable)]
/// A basic JWT header part, the alg is automatically filled for use
/// It's missing things like the kid but that's for later
pub struct Header {
    typ: String,
    alg: Algorithm,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_owned(),
            alg: algorithm,
        }
    }
}

/// Take the payload of a JWT and sign it using the algorithm given.
/// Returns the base64 url safe encoded of the hmac result
fn sign(data: &str, secret: &[u8], algorithm: Algorithm) -> String {
    fn crypt<D: Digest>(digest: D, data: &str, secret: &[u8]) -> String {
        let mut hmac = Hmac::new(digest, secret);
        hmac.input(data.as_bytes());
        hmac.result().code().to_base64(base64::URL_SAFE)
    }

    match algorithm {
        Algorithm::HS256 => crypt(Sha256::new(), data, secret),
        Algorithm::HS384 => crypt(Sha384::new(), data, secret),
        Algorithm::HS512 => crypt(Sha512::new(), data, secret),
    }
}

/// Compares the signature given with a re-computed signature
fn verify(signature: &str, data: &str, secret: &[u8], algorithm: Algorithm) -> bool {
    signature == sign(data, secret, algorithm)
}

/// Encode the claims passed and sign the payload using the algorithm and the secret
pub fn encode<T: Part, B: AsRef<[u8]>>(claims: &T, secret: B, algorithm: Algorithm) -> Result<String, Error> {
    let encoded_header = try!(Header::new(algorithm).to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header, encoded_claims].join(".");
    let signature = sign(&*payload, secret.as_ref(), algorithm);

    Ok([payload, signature].join("."))
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
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

    // not reachable right now
    let header = try!(Header::from_base64(parts[0]));
    if header.alg != algorithm {
        return Err(Error::WrongAlgorithmHeader);
    }

    let claims: T = try!(T::from_base64(parts[1]));
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::{encode, decode, Algorithm, Header, Part, sign, verify};

    #[derive(Debug, PartialEq, Clone, RustcEncodable, RustcDecodable)]
    struct Claims {
        sub: String,
        company: String
    }

    #[test]
    fn to_base64() {
        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".to_owned();
        let result = Header::new(Algorithm::HS256).to_base64();

        assert_eq!(expected, result.unwrap());
    }

    #[test]
    fn from_base64() {
        let encoded = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
        let header = Header::from_base64(encoded).unwrap();

        assert_eq!(header.typ, "JWT");
        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[test]
    fn round_trip_base64() {
        let header = Header::new(Algorithm::HS256);
        assert_eq!(Header::from_base64(header.to_base64().unwrap()).unwrap(), header);
    }

    #[test]
    fn sign_hs256() {
        let result = sign("hello world", b"secret", Algorithm::HS256);
        let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        assert_eq!(result, expected);
    }

    #[test]
    fn verify_hs256() {
        let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
        let valid = verify(sig, "hello world", b"secret", Algorithm::HS256);
        assert!(valid);
    }

    #[test]
    fn round_trip_claim() {
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let token = encode(&my_claims, "secret", Algorithm::HS256).unwrap();
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256).unwrap();
        assert_eq!(my_claims, claims);
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
        claims.unwrap();
    }
}

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
use crypto::util::fixed_time_eq;

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
    type Encoded: AsRef<str>;

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<Self, Error> where Self: Sized;
    fn to_base64(&self) -> Result<Self::Encoded, Error>;
}

impl<T> Part for T where T: Encodable + Decodable {
    type Encoded = String;

    fn to_base64(&self) -> Result<Self::Encoded, Error> {
        let encoded = try!(json::encode(&self));
        Ok(encoded.as_bytes().to_base64(base64::URL_SAFE))
    }

    fn from_base64<B: AsRef<[u8]>>(encoded: B) -> Result<T, Error> {
        let decoded = try!(encoded.as_ref().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(json::decode(&s)))
    }
}

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
/// A basic JWT header part, the alg is automatically filled for use
/// and the algorithm defaults to HS256
pub struct Header {
    typ: String,
    alg: Algorithm,
    jku: Option<String>,
    kid: Option<String>,
    x5u: Option<String>,
    x5t: Option<String>
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_owned(),
            alg: algorithm,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header::new(Algorithm::HS256)
    }
}

#[derive(Debug)]
pub struct TokenData<T: Part> {
    header: Header,
    claims: T
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
    fixed_time_eq(signature.as_ref(), sign(data, secret, algorithm).as_ref())
}

/// Encode the claims passed and sign the payload using the algorithm and the secret
pub fn encode<T: Part, B: AsRef<[u8]>>(claims: &T, secret: B, header: Header) -> Result<String, Error> {
    let encoded_header = try!(header.to_base64());
    let encoded_claims = try!(claims.to_base64());
    // seems to be a tiny bit faster than format!("{}.{}", x, y)
    let payload = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*payload, secret.as_ref(), header.alg);

    Ok([payload, signature].join("."))
}

/// Decode a token into a Claims struct
/// If the token or its signature is invalid, it will return an error
pub fn decode<T: Part>(token: &str, secret: &[u8], algorithm: Algorithm) -> Result<TokenData<T>, Error> {
    // We don't use AsRef<[u8]> for `secret` because it would require changing this:
    //     decode::<MyStruct>(...)
    // to:
    //     decode::<MyStruct, _>(...)

    macro_rules! expect_two {
        ($iter:expr) => {{
            let mut i = $iter; // evaluate the expr
            match (i.next(), i.next(), i.next()) {
                (Some(first), Some(second), None) => (first, second),
                _ => return Err(Error::InvalidToken)
            }
        }}
    }

    let (signature, payload) = expect_two!(token.rsplitn(2, '.'));

    let is_valid = verify(
        signature,
        payload,
        secret,
        algorithm
    );

    if !is_valid {
        return Err(Error::InvalidSignature);
    }

    let (claims, header) = expect_two!(payload.rsplitn(2, '.'));

    let header = try!(Header::from_base64(header));
    if header.alg != algorithm {
        return Err(Error::WrongAlgorithmHeader);
    }
    let decoded_claims = try!(T::from_base64(claims));

    Ok(TokenData { header: header, claims: decoded_claims})
}

#[cfg(test)]
mod tests {
    use super::{encode, decode, Algorithm, Header, sign, verify};

    #[derive(Debug, PartialEq, Clone, RustcEncodable, RustcDecodable)]
    struct Claims {
        sub: String,
        company: String
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
    fn encode_with_custom_header() {
        // TODO: test decode value
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let mut header = Header::default();
        header.kid = Some("kid".to_owned());
        let token = encode(&my_claims, "secret", header).unwrap();
        let token_data = decode::<Claims>(&token, "secret".as_ref(), Algorithm::HS256).unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert_eq!("kid", token_data.header.kid.unwrap());
    }

    #[test]
    fn round_trip_claim() {
        let my_claims = Claims {
            sub: "b@b.com".to_owned(),
            company: "ACME".to_owned()
        };
        let token = encode(&my_claims, "secret", Header::default()).unwrap();
        let token_data = decode::<Claims>(&token, "secret".as_ref(), Algorithm::HS256).unwrap();
        assert_eq!(my_claims, token_data.claims);
        assert!(token_data.header.kid.is_none());
    }

    #[test]
    #[should_panic(expected = "InvalidToken")]
    fn decode_token_missing_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn decode_token_invalid_signature() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        claims.unwrap();
    }

    #[test]
    fn decode_token_with_bytes_secret() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29tcGFueSI6Ikdvb2dvbCJ9.27QxgG96vpX4akKNpD1YdRGHE3_u2X35wR3EHA2eCrs";
        let claims = decode::<Claims>(token, b"\x01\x02\x03", Algorithm::HS256);
        assert!(claims.is_ok());
    }

    #[test]
    fn decode_token_with_shuffled_header_fields() {
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.SEIZ4Jg46VGhquuwPYDLY5qHF8AkQczF14aXM3a2c28";
        let claims = decode::<Claims>(token, "secret".as_ref(), Algorithm::HS256);
        assert!(claims.is_ok());
    }
}

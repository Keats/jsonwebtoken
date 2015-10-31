use rustc_serialize::json;
use rustc_serialize::base64::{self, ToBase64, FromBase64};

use errors::Error;


#[derive(Debug, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Header {
    typ: Option<String>,
    alg: String,
}

impl Header {
    pub fn new(algorithm: String) -> Header {
        Header {
            typ: Some("JWT".to_owned()),
            alg: algorithm,
        }
    }
    pub fn to_base64(&self) -> Result<String, Error> {
        let encoded = try!(json::encode(&self));
        Ok(encoded.as_bytes().to_base64(base64::STANDARD))
    }

    pub fn from_base64(encoded: String) -> Result<Header, Error> {
        let decoded = try!(encoded.as_bytes().from_base64());
        let s = try!(String::from_utf8(decoded));
        Ok(try!(json::decode(&s)))
    }
}

#[cfg(test)]
mod tests {
    use header::Header;

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

        assert_eq!(header.typ.unwrap(), "JWT");
        assert_eq!(header.alg, "HS256");
    }

    #[test]
    fn round_trip() {
        let header = Header::new("HS256".to_owned());
        assert_eq!(Header::from_base64(header.to_base64().unwrap()).unwrap(), header);
    }
}

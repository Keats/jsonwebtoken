use std::collections::BTreeMap;
use rustc_serialize::json::{self, Json, ToJson};
use rustc_serialize::base64::{self, ToBase64, FromBase64};

use errors::Error;

macro_rules! add_registered_claims {
    ($map: expr, $key: expr, $reg: expr) => {
        if let Some(val) = $reg {
            $map.insert($key, val.to_json());
        }
    }
}

#[derive(Debug, Default, RustcEncodable, RustcDecodable)]
struct RegisteredClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
}

#[derive(Debug)]
pub struct Claims {
    registered: RegisteredClaims,
    private: BTreeMap<String, Json>,
}

impl Claims {
    pub fn new() -> Claims {
        Claims {
            registered: Default::default(),
            private: BTreeMap::new(),
        }
    }

    fn to_base64(self) -> Result<String, Error> {
        let mut map: BTreeMap<String, Json> = BTreeMap::new();
        // just encoding the struct would give null values in the resulting json
        // like {"iss": null}, which we don't want
        add_registered_claims!(map, "iss".to_owned(), self.registered.iss);
        add_registered_claims!(map, "sub".to_owned(), self.registered.sub);
        add_registered_claims!(map, "aud".to_owned(), self.registered.aud);
        add_registered_claims!(map, "exp".to_owned(), self.registered.exp);
        add_registered_claims!(map, "nbf".to_owned(), self.registered.nbf);
        add_registered_claims!(map, "iat".to_owned(), self.registered.iat);
        add_registered_claims!(map, "jti".to_owned(), self.registered.jti);

        map.extend(self.private);
        let encoded = try!(json::encode(&map));
        Ok(encoded.as_bytes().to_base64(base64::STANDARD))
    }

    fn from_base64(encoded String) -> Result<Claims, Error> {

    }

    pub fn add<T: ToJson>(&mut self, key: String, value: T) {
        self.private.insert(key, value.to_json());
    }
}

#[cfg(test)]
mod tests {
    use claims::Claims;
    use rustc_serialize::json::{ToJson};

    #[test]
    fn to_base64_no_null_values() {
        let mut claims = Claims::new();
        claims.registered.iss = Some("JWT".to_owned());
        let result = claims.to_base64().unwrap();
        let expected = "eyJpc3MiOiJKV1QifQ==";

        assert_eq!(result, expected);
    }

    #[test]
    fn to_base64_custom_claims() {
        let mut claims = Claims::new();
        claims.add::<String>("group".to_owned(), "zombie".to_owned());
        let result = claims.to_base64().unwrap();
        let expected = "eyJncm91cCI6InpvbWJpZSJ9";

        assert_eq!(result, expected);
    }

    #[test]
    fn to_base64_registered_and_customs() {
        let mut claims = Claims::new();
        claims.registered.iss = Some("JWT".to_owned());
        claims.add::<String>("group".to_owned(), "zombie".to_owned());
        let result = claims.to_base64().unwrap();
        let expected = "eyJncm91cCI6InpvbWJpZSIsImlzcyI6IkpXVCJ9";

        assert_eq!(result, expected);
    }
}

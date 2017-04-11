use chrono::UTC;
use serde::ser::Serialize;
use serde_json::{Value, from_value, to_value};
use serde_json::map::Map;

use errors::{Result, ErrorKind};


#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    pub leeway: i64,
    pub validate_signature: bool,
    pub validate_exp: bool,
    pub validate_iat: bool,
    pub validate_nbf: bool,

    pub aud: Option<Value>,
    pub iss: Option<String>,
    pub sub: Option<String>,
}

impl Validation {
    pub fn set_audience<T: Serialize>(&mut self, audience: &T) {
        self.aud = Some(to_value(audience).unwrap());
    }
}

impl Default for Validation {
    fn default() -> Validation {
        Validation {
            leeway: 0,

            validate_signature: true,

            validate_exp: true,
            validate_iat: true,
            validate_nbf: true,

            iss: None,
            sub: None,
            aud: None,
        }
    }
}



pub fn validate(claims: &Map<String, Value>, options: &Validation) -> Result<()> {
    let now = UTC::now().timestamp();

    if let Some(iat) = claims.get("iat") {
        if options.validate_iat && from_value::<i64>(iat.clone())? > now + options.leeway {
            return Err(ErrorKind::InvalidIssuedAt.into());
        }
    }

    if let Some(exp) = claims.get("exp") {
        if options.validate_exp && from_value::<i64>(exp.clone())? < now - options.leeway {
            return Err(ErrorKind::ExpiredSignature.into());
        }
    }

    if let Some(nbf) = claims.get("nbf") {
        if options.validate_nbf && from_value::<i64>(nbf.clone())? > now + options.leeway {
            return Err(ErrorKind::ImmatureSignature.into());
        }
    }

    if let Some(iss) = claims.get("iss") {
        if let Some(ref correct_iss) = options.iss {
            if from_value::<String>(iss.clone())? != *correct_iss {
                return Err(ErrorKind::InvalidIssuer.into());
            }
        }
    }

    if let Some(sub) = claims.get("sub") {
        if let Some(ref correct_sub) = options.sub {
            if from_value::<String>(sub.clone())? != *correct_sub {
                return Err(ErrorKind::InvalidSubject.into());
            }
        }
    }

    if let Some(aud) = claims.get("aud") {
        if let Some(ref correct_aud) = options.aud {
            if aud != correct_aud {
                return Err(ErrorKind::InvalidAudience.into());
            }
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use serde_json::{to_value};
    use serde_json::map::Map;
    use chrono::UTC;

    use super::{validate, Validation};

    use errors::ErrorKind;

    #[test]
    fn iat_in_past_ok() {
        let mut claims = Map::new();
        claims.insert("iat".to_string(), to_value(UTC::now().timestamp() - 10000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_ok());
    }

    #[test]
    fn iat_in_future_fails() {
        let mut claims = Map::new();
        claims.insert("iat".to_string(), to_value(UTC::now().timestamp() + 100000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::InvalidIssuedAt => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn iat_in_future_but_in_leeway_ok() {
        let mut claims = Map::new();
        claims.insert("iat".to_string(), to_value(UTC::now().timestamp() + 50).unwrap());
        let validation = Validation {
            leeway: 1000 * 60,
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn exp_in_future_ok() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(UTC::now().timestamp() + 10000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_ok());
    }

    #[test]
    fn exp_in_past_fails() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(UTC::now().timestamp() - 100000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::ExpiredSignature => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn exp_in_past_but_in_leeway_ok() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(UTC::now().timestamp() - 500).unwrap());
        let validation = Validation {
            leeway: 1000 * 60,
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn nbf_in_past_ok() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(UTC::now().timestamp() - 10000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_ok());
    }

    #[test]
    fn nbf_in_future_fails() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(UTC::now().timestamp() + 100000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::ImmatureSignature => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn nbf_in_future_but_in_leeway_ok() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(UTC::now().timestamp() + 500).unwrap());
        let validation = Validation {
            leeway: 1000 * 60,
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_ok() {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), to_value("Keats").unwrap());
        let validation = Validation {
            iss: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_not_matching_fails() {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), to_value("Hacked").unwrap());
        let validation = Validation {
            iss: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::InvalidIssuer => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn sub_ok() {
        let mut claims = Map::new();
        claims.insert("sub".to_string(), to_value("Keats").unwrap());
        let validation = Validation {
            sub: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn sub_not_matching_fails() {
        let mut claims = Map::new();
        claims.insert("sub".to_string(), to_value("Hacked").unwrap());
        let validation = Validation {
            sub: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::InvalidSubject => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn aud_string_ok() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value("Everyone").unwrap());
        let mut validation = Validation::default();
        validation.set_audience(&"Everyone");
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_array_of_string_ok() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value(["UserA", "UserB"]).unwrap());
        let mut validation = Validation::default();
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_type_mismatch_fails() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value("Everyone").unwrap());
        let mut validation = Validation::default();
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::InvalidAudience => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn aud_correct_type_not_matching_fails() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value("Everyone").unwrap());
        let mut validation = Validation::default();
        validation.set_audience(&"None");
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            &ErrorKind::InvalidAudience => (),
            _ => assert!(false),
        };
    }
}

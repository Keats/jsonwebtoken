use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::map::Map;
use serde_json::Value;

use crate::algorithms::Algorithm;
use crate::errors::{new_error, ErrorKind, Result};

/// Contains the various validations that are applied after decoding a JWT.
///
/// All time validation happen on UTC timestamps as seconds.
///
/// ```rust
/// use jsonwebtoken::Validation;
///
/// // Default value
/// let validation = Validation::default();
///
/// // Changing one parameter
/// let mut validation = Validation {leeway: 60, ..Default::default()};
///
/// // Setting audience
/// let mut validation = Validation::default();
/// validation.set_audience(&["Me"]); // a single string
/// validation.set_audience(&["Me", "You"]); // array of strings
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    /// Add some leeway (in seconds) to the `exp`, `iat` and `nbf` validation to
    /// account for clock skew.
    ///
    /// Defaults to `0`.
    pub leeway: u64,
    /// Whether to validate the `exp` field.
    ///
    /// It will return an error if the time in the `exp` field is past.
    ///
    /// Defaults to `true`.
    pub validate_exp: bool,
    /// Whether to validate the `nbf` field.
    ///
    /// It will return an error if the current timestamp is before the time in the `nbf` field.
    ///
    /// Defaults to `false`.
    pub validate_nbf: bool,
    /// If it contains a value, the validation will check that the `aud` field is a member of the
    /// audience provided and will error otherwise.
    ///
    /// Defaults to `None`.
    pub aud: Option<HashSet<String>>,
    /// If it contains a value, the validation will check that the `iss` field is a member of the
    /// iss provided and will error otherwise.
    ///
    /// Defaults to `None`.
    pub iss: Option<HashSet<String>>,
    /// If it contains a value, the validation will check that the `sub` field is the same as the
    /// one provided and will error otherwise.
    ///
    /// Defaults to `None`.
    pub sub: Option<String>,
    /// If it contains a value, the validation will check that the `alg` of the header is contained
    /// in the ones provided and will error otherwise.
    ///
    /// Defaults to `vec![Algorithm::HS256]`.
    pub algorithms: Vec<Algorithm>,
}

impl Validation {
    /// Create a default validation setup allowing the given alg
    pub fn new(alg: Algorithm) -> Validation {
        Validation { algorithms: vec![alg], ..Default::default() }
    }

    /// `aud` is a collection of one or more acceptable audience members
    pub fn set_audience<T: ToString>(&mut self, items: &[T]) {
        self.aud = Some(items.iter().map(|x| x.to_string()).collect())
    }

    /// `iss` is a collection of one or more acceptable iss members
    pub fn set_iss<T: ToString>(&mut self, items: &[T]) {
        self.iss = Some(items.iter().map(|x| x.to_string()).collect())
    }
}

impl Default for Validation {
    fn default() -> Validation {
        Validation {
            leeway: 0,

            validate_exp: true,
            validate_nbf: false,

            iss: None,
            sub: None,
            aud: None,

            algorithms: vec![Algorithm::HS256],
        }
    }
}

/// Gets the current timestamp in the format JWT expect
pub fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs()
}

pub fn validate(claims: &Map<String, Value>, options: &Validation) -> Result<()> {
    let now = get_current_timestamp();

    if options.validate_exp {
        if let Some(exp) = claims.get("exp") {
            if let Some(exp) = exp.as_u64() {
                if exp < now - options.leeway {
                    return Err(new_error(ErrorKind::ExpiredSignature));
                }
            } else {
                return Err(new_error(ErrorKind::ExpiredSignature));
            }
        } else {
            return Err(new_error(ErrorKind::ExpiredSignature));
        }
    }

    if options.validate_nbf {
        if let Some(nbf) = claims.get("nbf") {
            if let Some(nbf) = nbf.as_u64() {
                if nbf > now + options.leeway {
                    return Err(new_error(ErrorKind::ImmatureSignature));
                }
            } else {
                return Err(new_error(ErrorKind::ImmatureSignature));
            }
        } else {
            return Err(new_error(ErrorKind::ImmatureSignature));
        }
    }

    if let Some(ref correct_sub) = options.sub {
        if let Some(Value::String(sub)) = claims.get("sub") {
            if sub != correct_sub {
                return Err(new_error(ErrorKind::InvalidSubject));
            }
        } else {
            return Err(new_error(ErrorKind::InvalidSubject));
        }
    }

    if let Some(ref correct_iss) = options.iss {
        if let Some(Value::String(iss)) = claims.get("iss") {
            if !correct_iss.contains(iss) {
                return Err(new_error(ErrorKind::InvalidIssuer));
            }
        } else {
            return Err(new_error(ErrorKind::InvalidIssuer));
        }
    }

    if let Some(ref correct_aud) = options.aud {
        if let Some(aud) = claims.get("aud") {
            match aud {
                Value::String(aud) => {
                    if !correct_aud.contains(aud) {
                        return Err(new_error(ErrorKind::InvalidAudience));
                    }
                }
                Value::Array(_) => {
                    use serde::Deserialize;
                    let aud = HashSet::<String>::deserialize(aud)?;
                    if aud.intersection(correct_aud).next().is_none() {
                        return Err(new_error(ErrorKind::InvalidAudience));
                    }
                }
                _ => return Err(new_error(ErrorKind::InvalidAudience)),
            };
        } else {
            return Err(new_error(ErrorKind::InvalidAudience));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::map::Map;
    use serde_json::to_value;

    use super::{get_current_timestamp, validate, Validation};

    use crate::errors::ErrorKind;

    #[test]
    fn exp_in_future_ok() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(get_current_timestamp() + 10000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_ok());
    }

    #[test]
    fn exp_in_past_fails() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(get_current_timestamp() - 100000).unwrap());
        let res = validate(&claims, &Validation::default());
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn exp_in_past_but_in_leeway_ok() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(get_current_timestamp() - 500).unwrap());
        let validation = Validation { leeway: 1000 * 60, ..Default::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    fn validation_called_even_if_field_is_empty() {
        let claims = Map::new();
        let res = validate(&claims, &Validation::default());
        assert!(res.is_err());
        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn nbf_in_past_ok() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(get_current_timestamp() - 10000).unwrap());
        let validation =
            Validation { validate_exp: false, validate_nbf: true, ..Validation::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn nbf_in_future_fails() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(get_current_timestamp() + 100000).unwrap());
        let validation =
            Validation { validate_exp: false, validate_nbf: true, ..Validation::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ImmatureSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn nbf_in_future_but_in_leeway_ok() {
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), to_value(get_current_timestamp() + 500).unwrap());
        let validation = Validation {
            leeway: 1000 * 60,
            validate_nbf: true,
            validate_exp: false,
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_ok() {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), to_value("Keats").unwrap());

        let mut iss = std::collections::HashSet::new();
        iss.insert("Keats".to_string());

        let validation = Validation { validate_exp: false, iss: Some(iss), ..Default::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_not_matching_fails() {
        let mut claims = Map::new();
        claims.insert("iss".to_string(), to_value("Hacked").unwrap());

        let mut iss = std::collections::HashSet::new();
        iss.insert("Keats".to_string());

        let validation = Validation { validate_exp: false, iss: Some(iss), ..Default::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn iss_missing_fails() {
        let claims = Map::new();

        let mut iss = std::collections::HashSet::new();
        iss.insert("Keats".to_string());

        let validation = Validation { validate_exp: false, iss: Some(iss), ..Default::default() };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn sub_ok() {
        let mut claims = Map::new();
        claims.insert("sub".to_string(), to_value("Keats").unwrap());
        let validation = Validation {
            validate_exp: false,
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
            validate_exp: false,
            sub: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidSubject => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn sub_missing_fails() {
        let claims = Map::new();
        let validation = Validation {
            validate_exp: false,
            sub: Some("Keats".to_string()),
            ..Default::default()
        };
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidSubject => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_string_ok() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value(["Everyone"]).unwrap());
        let mut validation = Validation { validate_exp: false, ..Validation::default() };
        validation.set_audience(&["Everyone"]);
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_array_of_string_ok() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value(["UserA", "UserB"]).unwrap());
        let mut validation = Validation { validate_exp: false, ..Validation::default() };
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(&claims, &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_type_mismatch_fails() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value(["Everyone"]).unwrap());
        let mut validation = Validation { validate_exp: false, ..Validation::default() };
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_correct_type_not_matching_fails() {
        let mut claims = Map::new();
        claims.insert("aud".to_string(), to_value(["Everyone"]).unwrap());
        let mut validation = Validation { validate_exp: false, ..Validation::default() };
        validation.set_audience(&["None"]);
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_missing_fails() {
        let claims = Map::new();
        let mut validation = Validation { validate_exp: false, ..Validation::default() };
        validation.set_audience(&["None"]);
        let res = validate(&claims, &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    #[should_panic]
    fn does_validation_in_right_order() {
        let mut claims = Map::new();
        claims.insert("exp".to_string(), to_value(get_current_timestamp() + 10000).unwrap());

        let mut iss = std::collections::HashSet::new();
        iss.insert("iss no check".to_string());

        let v = Validation {
            leeway: 5,
            validate_exp: true,
            iss: Some(iss),
            sub: Some("sub no check".to_string()),
            ..Validation::default()
        };
        let res = validate(&claims, &v);
        // It errors because it needs to validate iss/sub which are missing
        assert!(res.is_err());
        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            t => panic!("{:?}", t),
        };
    }

    // https://github.com/Keats/jsonwebtoken/issues/110
    #[test]
    fn aud_use_validation_struct() {
        let mut claims = Map::new();
        claims.insert(
            "aud".to_string(),
            to_value("my-googleclientid1234.apps.googleusercontent.com").unwrap(),
        );

        let aud = "my-googleclientid1234.apps.googleusercontent.com".to_string();
        let mut aud_hashset = std::collections::HashSet::new();
        aud_hashset.insert(aud);

        let validation =
            Validation { aud: Some(aud_hashset), validate_exp: false, ..Validation::default() };
        let res = validate(&claims, &validation);
        println!("{:?}", res);
        assert!(res.is_ok());
    }
}

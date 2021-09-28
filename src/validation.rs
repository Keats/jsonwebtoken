use std::borrow::Cow;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::algorithms::Algorithm;
use crate::errors::{new_error, ErrorKind, Result};

/// Contains the various validations that are applied after decoding a JWT.
///
/// All time validation happen on UTC timestamps as seconds.
///
/// ```rust
/// use jsonwebtoken::{Validation, Algorithm};
///
/// let mut validation = Validation::new(Algorithm::HS256);
/// validation.leeway = 5;
/// // Setting audience
/// validation.set_audience(&["Me"]); // a single string
/// validation.set_audience(&["Me", "You"]); // array of strings
/// // or issuer
/// validation.set_iss(&["Me"]); // a single string
/// validation.set_iss(&["Me", "You"]); // array of strings
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
    /// The validation will check that the `alg` of the header is contained
    /// in the ones provided and will error otherwise. Will error if it is empty.
    ///
    /// Defaults to `vec![Algorithm::HS256]`.
    pub algorithms: Vec<Algorithm>,

    /// Whether to validate the JWT signature. Very insecure to turn that off
    pub(crate) validate_signature: bool,
}

impl Validation {
    /// Create a default validation setup allowing the given alg
    pub fn new(alg: Algorithm) -> Validation {
        Validation {
            algorithms: vec![alg],
            leeway: 0,

            validate_exp: true,
            validate_nbf: false,

            iss: None,
            sub: None,
            aud: None,

            validate_signature: true,
        }
    }

    /// `aud` is a collection of one or more acceptable audience members
    pub fn set_audience<T: ToString>(&mut self, items: &[T]) {
        self.aud = Some(items.iter().map(|x| x.to_string()).collect())
    }

    /// `iss` is a collection of one or more acceptable iss members
    pub fn set_iss<T: ToString>(&mut self, items: &[T]) {
        self.iss = Some(items.iter().map(|x| x.to_string()).collect())
    }

    /// Whether to validate the JWT cryptographic signature
    /// Very insecure to turn that off, only do it if you know what you're doing.
    /// With this flag turned off, you should not trust any of the values of the claims.
    pub fn insecure_disable_signature_validation(&mut self) {
        self.validate_signature = false;
    }
}

/// Gets the current timestamp in the format JWT expect
pub fn get_current_timestamp() -> u64 {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs()
}

#[derive(Deserialize)]
pub(crate) struct ClaimsForValidation<'a> {
    exp: TryParse<u64>,
    nbf: TryParse<u64>,
    #[serde(borrow)]
    sub: TryParse<Cow<'a, str>>,
    #[serde(borrow)]
    iss: TryParse<Cow<'a, str>>,
    #[serde(borrow)]
    aud: TryParse<Audience<'a>>,
}
enum TryParse<T> {
    Parsed(T),
    FailedToParse,
    NotPresent,
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for TryParse<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(deserializer) {
            Ok(Some(value)) => TryParse::Parsed(value),
            Ok(None) => TryParse::NotPresent,
            Err(_) => TryParse::FailedToParse,
        })
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience<'a> {
    Single(#[serde(borrow)] Cow<'a, str>),
    Multiple(#[serde(borrow)] HashSet<BorrowedCowIfPossible<'a>>),
}
/// Usually #[serde(borrow)] on `Cow` enables deserializing with no allocations where
/// possible (no escapes in the original str) but it does not work on e.g. `HashSet<Cow<str>>`
/// We use this struct in this case.
#[derive(Deserialize, PartialEq, Eq, Hash)]
struct BorrowedCowIfPossible<'a>(#[serde(borrow)] Cow<'a, str>);
impl std::borrow::Borrow<str> for BorrowedCowIfPossible<'_> {
    fn borrow(&self) -> &str {
        &*self.0
    }
}

pub(crate) fn validate(claims: ClaimsForValidation, options: &Validation) -> Result<()> {
    let now = get_current_timestamp();

    if options.validate_exp
        && !matches!(claims.exp, TryParse::Parsed(exp) if exp >= now-options.leeway)
    {
        return Err(new_error(ErrorKind::ExpiredSignature));
    }

    if options.validate_nbf
        && !matches!(claims.nbf, TryParse::Parsed(nbf) if nbf <= now + options.leeway)
    {
        return Err(new_error(ErrorKind::ImmatureSignature));
    }

    if let Some(correct_sub) = options.sub.as_deref() {
        if !matches!(claims.sub, TryParse::Parsed(sub) if sub == correct_sub) {
            return Err(new_error(ErrorKind::InvalidSubject));
        }
    }

    if let Some(ref correct_iss) = options.iss {
        if !matches!(claims.iss, TryParse::Parsed(iss) if correct_iss.contains(&*iss)) {
            return Err(new_error(ErrorKind::InvalidIssuer));
        }
    }

    if let Some(ref correct_aud) = options.aud {
        match claims.aud {
            TryParse::Parsed(Audience::Single(aud)) if correct_aud.contains(&*aud) => {}
            TryParse::Parsed(Audience::Multiple(aud))
                if {
                    // Check that intersection is non-empty, favoring iterating on smallest
                    if correct_aud.len() < aud.len() {
                        correct_aud.iter().any(|a| aud.contains(&**a))
                    } else {
                        aud.iter().any(|a| correct_aud.contains(&*a.0))
                    }
                } => {}
            _ => return Err(new_error(ErrorKind::InvalidAudience)),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{get_current_timestamp, validate, ClaimsForValidation, Validation};

    use crate::errors::ErrorKind;
    use crate::Algorithm;

    fn deserialize_claims(claims: &serde_json::Value) -> ClaimsForValidation {
        serde::Deserialize::deserialize(claims).unwrap()
    }

    #[test]
    fn exp_in_future_ok() {
        let claims = json!({ "exp": get_current_timestamp() + 10000 });
        let res = validate(deserialize_claims(&claims), &Validation::new(Algorithm::HS256));
        assert!(res.is_ok());
    }

    #[test]
    fn exp_in_past_fails() {
        let claims = json!({ "exp": get_current_timestamp() - 100000 });
        let res = validate(deserialize_claims(&claims), &Validation::new(Algorithm::HS256));
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn exp_in_past_but_in_leeway_ok() {
        let claims = json!({ "exp": get_current_timestamp() - 500 });
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 1000 * 60;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    fn validation_called_even_if_field_is_empty() {
        let claims = json!({});
        let res = validate(deserialize_claims(&claims), &Validation::new(Algorithm::HS256));
        assert!(res.is_err());
        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn nbf_in_past_ok() {
        let claims = json!({ "nbf": get_current_timestamp() - 10000 });
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_nbf = true;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn nbf_in_future_fails() {
        let claims = json!({ "nbf": get_current_timestamp() + 100000 });
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_nbf = true;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ImmatureSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn nbf_in_future_but_in_leeway_ok() {
        let claims = json!({ "nbf": get_current_timestamp() + 500 });
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_nbf = true;
        validation.leeway = 1000 * 60;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_ok() {
        let claims = json!({"iss": "Keats"});

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_iss(&["Keats"]);

        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn iss_not_matching_fails() {
        let claims = json!({"iss": "Hacked"});

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_iss(&["Keats"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn iss_missing_fails() {
        let claims = json!({});

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_iss(&["Keats"]);
        let res = validate(deserialize_claims(&claims), &validation);

        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn sub_ok() {
        let claims = json!({"sub": "Keats"});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.sub = Some("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn sub_not_matching_fails() {
        let claims = json!({"sub": "Hacked"});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.sub = Some("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidSubject => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn sub_missing_fails() {
        let claims = json!({});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.sub = Some("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidSubject => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_string_ok() {
        let claims = json!({"aud": ["Everyone"]});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["Everyone"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_array_of_string_ok() {
        let claims = json!({"aud": ["UserA", "UserB"]});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    fn aud_type_mismatch_fails() {
        let claims = json!({"aud": ["Everyone"]});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["UserA", "UserB"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_correct_type_not_matching_fails() {
        let claims = json!({"aud": ["Everyone"]});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["None"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    #[test]
    fn aud_missing_fails() {
        let claims = json!({});
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["None"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidAudience => (),
            _ => unreachable!(),
        };
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    fn does_validation_in_right_order() {
        let claims = json!({ "exp": get_current_timestamp() + 10000 });

        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 5;
        validation.set_iss(&["iss no check"]);
        validation.set_audience(&["iss no check"]);

        let res = validate(deserialize_claims(&claims), &validation);
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
        let claims = json!({"aud": "my-googleclientid1234.apps.googleusercontent.com"});

        let aud = "my-googleclientid1234.apps.googleusercontent.com".to_string();
        let mut aud_hashset = std::collections::HashSet::new();
        aud_hashset.insert(aud);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.set_audience(&["my-googleclientid1234.apps.googleusercontent.com"]);

        let res = validate(deserialize_claims(&claims), &validation);
        println!("{:?}", res);
        assert!(res.is_ok());
    }
}

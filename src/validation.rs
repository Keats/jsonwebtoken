use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

use crate::algorithms::{Algorithm, AlgorithmFamily};
use crate::errors::{ErrorKind, Result, new_error};

/// The only values that will be considered are "exp", "nbf", "aud", "iss", "sub".
const AUDIENCE_CLAIM: &str = "aud";
const EXPIRY_CLAIM: &str = "exp";
const ISSUER_CLAIM: &str = "iss";
const NOT_BEFORE_CLAIM: &str = "nbf";
const SUBJECT_CLAIM: &str = "sub";

/// Contains the various validations that are applied after decoding a JWT.
///
/// All time validation happen on UTC timestamps as seconds.
///
/// ```rust
/// use jsonwebtoken::{Validation, Algorithm};
///
/// let mut validation = Validation::new().with_algorithm(Algorithm::HS256);
/// validation.leeway = 5;
/// // Setting audience
/// validation.set_audience(&["Me"]); // a single string
/// validation.set_audience(&["Me", "You"]); // array of strings
/// // or issuer
/// validation.set_issuer(&["Me"]); // a single string
/// validation.set_issuer(&["Me", "You"]); // array of strings
/// // Setting required claims
/// validation.set_required_spec_claims(&["exp", "iss", "aud"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    /// Which claims are required to be present before starting the validation.
    /// This does not interact with the various `validate_*`. If you remove `exp` from that list, you still need
    /// to set `validate_exp` to `false`.
    /// The only value that will be used are "exp", "nbf", "aud", "iss", "sub". Anything else will be ignored.
    ///
    /// Defaults to `{"exp"}`
    required_spec_claims: HashSet<String>,
    /// Add some leeway (in seconds) to the `exp` and `nbf` validation to
    /// account for clock skew.
    ///
    /// Defaults to `60`.
    leeway: u64,
    /// Reject a token some time (in seconds) before the `exp` to prevent
    /// expiration in transit over the network.
    ///
    /// The value is the inverse of `leeway`, subtracting from the validation time.
    ///
    /// Defaults to `0`.
    reject_tokens_expiring_in_less_than: u64,
    /// Whether to validate the `exp` field.
    ///
    /// It will return an error if the time in the `exp` field is past.
    ///
    /// Defaults to `true`.
    validate_exp: bool,
    /// Whether to validate the `nbf` field.
    ///
    /// It will return an error if the current timestamp is before the time in the `nbf` field.
    ///
    /// Validation only happens if `nbf` claim is present in the token.
    /// Adding `nbf` to `required_spec_claims` will make it required.
    ///
    /// Defaults to `false`.
    validate_nbf: bool,
    /// Whether to validate the `aud` field.
    ///
    /// It will return an error if the `aud` field is not a member of the audience provided.
    ///
    /// Validation only happens if `aud` claim is present in the token.
    /// Adding `aud` to `required_spec_claims` will make it required.
    ///
    /// Defaults to `true`. Very insecure to turn this off. Only do this if you know what you are doing.
    validate_aud: bool,
    /// Validation will check that the `aud` field is a member of the
    /// audience provided and will error otherwise.
    /// Use `set_audience` to set it
    ///
    /// Validation only happens if `aud` claim is present in the token.
    /// Adding `aud` to `required_spec_claims` will make it required.
    ///
    /// Defaults to `None`.
    aud: Option<HashSet<String>>,
    /// If it contains a value, the validation will check that the `iss` field is a member of the
    /// iss provided and will error otherwise.
    /// Use `set_issuer` to set it
    ///
    /// Validation only happens if `iss` claim is present in the token.
    /// Adding `iss` to `required_spec_claims` will make it required.
    ///
    /// Defaults to `None`.
    iss: Option<HashSet<String>>,
    /// If it contains a value, the validation will check that the `sub` field is the same as the
    /// one provided and will error otherwise.
    ///
    /// Validation only happens if `sub` claim is present in the token.
    /// Adding `sub` to `required_spec_claims` will make it required.
    ///
    /// Defaults to `None`.
    sub: Option<String>,
    /// The validation will check that the `alg` of the header is contained
    /// in the ones provided and will error otherwise. Will error if it is empty.
    ///
    /// Defaults to `vec![Algorithm::HS256]`.
    pub(crate) algorithms: Vec<Algorithm>,

    /// Whether to validate the JWT signature. Very insecure to turn that off
    pub(crate) validate_signature: bool,
}

impl Validation {
    /// Create a default validation setup allowing the given alg
    pub fn new() -> Validation {
        Validation::default()
    }

    /// Create a default validation setup allowing the given alg
    pub fn with_algorithm(mut self, alg: Algorithm) -> Validation {
        // Self::new_impl(vec![alg])
        self.algorithms = vec![alg];
        self
    }

    /// Create a default validation setup allowing any algorithm in the family
    pub fn with_algorithm_family(mut self, family: AlgorithmFamily) -> Validation {
        self.algorithms = family.algorithms().to_vec();
        self
    }

    /// `aud` is a collection of one or more acceptable audience members
    /// The simple usage is `set_audience(&["some aud name"])`
    /// Makes the `aud` claim required by adding to `required_spec_claims`
    pub fn with_audience<T: ToString>(mut self, items: &[T]) -> Validation {
        self.required_spec_claims.insert(AUDIENCE_CLAIM.to_string());
        self.aud = Some(items.iter().map(|x| x.to_string()).collect());
        self.validate_aud = true;
        self
    }

    /// `iss` is a collection of one or more acceptable issuers members
    /// The simple usage is `set_issuer(&["some iss name"])`
    /// Makes the `iss` claim required by adding to `required_spec_claims`
    pub fn with_issuer<T: ToString>(mut self, items: &[T]) -> Validation {
        self.required_spec_claims.insert(ISSUER_CLAIM.to_string());
        self.iss = Some(items.iter().map(|x| x.to_string()).collect());
        self
    }

    /// TODO: docs
    pub fn with_subject<T: ToString>(mut self, subject: T) -> Validation {
        self.required_spec_claims.insert(SUBJECT_CLAIM.to_string());
        self.sub = Some(subject.to_string());
        self
    }

    /// TODO: docs
    pub fn with_exp(mut self, required: bool, validated: bool) -> Validation {
        if required {
            self.required_spec_claims.insert(EXPIRY_CLAIM.to_string());
        } else {
            self.required_spec_claims.remove(EXPIRY_CLAIM);
        }
        self.validate_exp = validated;
        self
    }

    /// TODO: docs
    pub fn with_nbf(mut self, required: bool, validated: bool) -> Validation {
        if required {
            self.required_spec_claims.insert(NOT_BEFORE_CLAIM.to_string());
        } else {
            self.required_spec_claims.remove(NOT_BEFORE_CLAIM);
        }
        self.validate_nbf = validated;
        self
    }

    /// TODO: docs
    pub fn with_leeway(mut self, seconds: u64) -> Validation {
        self.leeway = seconds;
        self
    }

    /// TODO: docs
    pub fn with_reject_tokens_expiring_in_less_than(mut self, seconds: u64) -> Validation {
        self.reject_tokens_expiring_in_less_than = seconds;
        self
    }

    /// Whether to validate the JWT cryptographic signature.
    /// Disabling validation is dangerous, only do it if you know what you're doing.
    /// With validation disabled you should not trust any of the values of the claims.
    #[deprecated(
        since = "10.1.0",
        note = "Use `jsonwebtoken::dangerous::insecure_decode` if you require this functionality."
    )]
    pub fn insecure_disable_signature_validation(&mut self) {
        self.validate_signature = false;
    }
}

impl Default for Validation {
    fn default() -> Self {
        let mut required_claims = HashSet::with_capacity(1);
        required_claims.insert("exp".to_owned());

        Validation {
            required_spec_claims: required_claims,
            algorithms: vec![Algorithm::HS256],
            leeway: 60,
            reject_tokens_expiring_in_less_than: 0,

            validate_exp: true,
            validate_nbf: false,
            validate_aud: false,

            iss: None,
            sub: None,
            aud: None,

            validate_signature: true,
        }
    }
}

/// Gets the current timestamp in the format expected by JWTs.
#[cfg(not(all(target_arch = "wasm32", not(any(target_os = "emscripten", target_os = "wasi")))))]
#[must_use]
pub fn get_current_timestamp() -> u64 {
    let start = std::time::SystemTime::now();
    start.duration_since(std::time::UNIX_EPOCH).expect("Time went backwards").as_secs()
}

/// Gets the current timestamp in the format expected by JWTs.
#[cfg(all(target_arch = "wasm32", not(any(target_os = "emscripten", target_os = "wasi"))))]
#[must_use]
pub fn get_current_timestamp() -> u64 {
    js_sys::Date::new_0().get_time() as u64 / 1000
}

#[derive(Deserialize)]
pub(crate) struct ClaimsForValidation<'a> {
    #[serde(deserialize_with = "numeric_type", default)]
    exp: TryParse<u64>,
    #[serde(deserialize_with = "numeric_type", default)]
    nbf: TryParse<u64>,
    #[serde(borrow)]
    sub: TryParse<Cow<'a, str>>,
    #[serde(borrow)]
    iss: TryParse<Issuer<'a>>,
    #[serde(borrow)]
    aud: TryParse<Audience<'a>>,
}

#[derive(Default, Debug)]
enum TryParse<T> {
    Parsed(T),
    FailedToParse,
    #[default]
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

#[derive(Deserialize)]
#[serde(untagged)]
enum Issuer<'a> {
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
        &self.0
    }
}

fn is_subset(reference: &HashSet<String>, given: &HashSet<BorrowedCowIfPossible<'_>>) -> bool {
    // Check that intersection is non-empty, favoring iterating on smallest
    if reference.len() < given.len() {
        reference.iter().any(|a| given.contains(&**a))
    } else {
        given.iter().any(|a| reference.contains(&*a.0))
    }
}

pub(crate) fn validate(claims: ClaimsForValidation, options: &Validation) -> Result<()> {
    for required_claim in &options.required_spec_claims {
        let present = match required_claim.as_str() {
            EXPIRY_CLAIM => matches!(claims.exp, TryParse::Parsed(_)),
            SUBJECT_CLAIM => matches!(claims.sub, TryParse::Parsed(_)),
            ISSUER_CLAIM => matches!(claims.iss, TryParse::Parsed(_)),
            AUDIENCE_CLAIM => matches!(claims.aud, TryParse::Parsed(_)),
            NOT_BEFORE_CLAIM => matches!(claims.nbf, TryParse::Parsed(_)),
            _ => continue,
        };

        if !present {
            return Err(new_error(ErrorKind::MissingRequiredClaim(required_claim.clone())));
        }
    }

    if options.validate_exp || options.validate_nbf {
        let now = get_current_timestamp();

        // Reject malformed exp/nbf claim when validation is enabled
        if options.validate_exp && matches!(claims.exp, TryParse::FailedToParse) {
            return Err(new_error(ErrorKind::InvalidClaimFormat("exp".to_string())));
        }
        if options.validate_nbf && matches!(claims.nbf, TryParse::FailedToParse) {
            return Err(new_error(ErrorKind::InvalidClaimFormat("nbf".to_string())));
        }

        if matches!(claims.exp, TryParse::Parsed(exp) if exp < options.reject_tokens_expiring_in_less_than)
        {
            return Err(new_error(ErrorKind::InvalidToken));
        }

        if matches!(claims.exp, TryParse::Parsed(exp) if options.validate_exp
            && exp - options.reject_tokens_expiring_in_less_than < now - options.leeway)
        {
            return Err(new_error(ErrorKind::ExpiredSignature));
        }

        if matches!(claims.nbf, TryParse::Parsed(nbf) if options.validate_nbf && nbf > now + options.leeway)
        {
            return Err(new_error(ErrorKind::ImmatureSignature));
        }
    }

    if let (TryParse::Parsed(sub), Some(correct_sub)) = (claims.sub, options.sub.as_deref())
        && sub != correct_sub
    {
        return Err(new_error(ErrorKind::InvalidSubject));
    }

    match (claims.iss, options.iss.as_ref()) {
        (TryParse::Parsed(Issuer::Single(iss)), Some(correct_iss))
            if !correct_iss.contains(&*iss) =>
        {
            return Err(new_error(ErrorKind::InvalidIssuer));
        }
        (TryParse::Parsed(Issuer::Multiple(iss)), Some(correct_iss))
            if !is_subset(correct_iss, &iss) =>
        {
            return Err(new_error(ErrorKind::InvalidIssuer));
        }
        _ => {}
    }

    if !options.validate_aud {
        return Ok(());
    }
    match (claims.aud, options.aud.as_ref()) {
        // Each principal intended to process the JWT MUST
        // identify itself with a value in the audience claim. If the principal
        // processing the claim does not identify itself with a value in the
        // "aud" claim when this claim is present, then the JWT MUST be
        //  rejected.
        (TryParse::Parsed(Audience::Multiple(aud)), None) if !aud.is_empty() => {
            return Err(new_error(ErrorKind::InvalidAudience));
        }
        (TryParse::Parsed(_), None) => {
            return Err(new_error(ErrorKind::InvalidAudience));
        }
        (TryParse::Parsed(Audience::Single(aud)), Some(correct_aud))
            if !correct_aud.contains(&*aud) =>
        {
            return Err(new_error(ErrorKind::InvalidAudience));
        }
        (TryParse::Parsed(Audience::Multiple(aud)), Some(correct_aud))
            if !is_subset(correct_aud, &aud) =>
        {
            return Err(new_error(ErrorKind::InvalidAudience));
        }
        _ => {}
    }

    Ok(())
}

fn numeric_type<'de, D>(deserializer: D) -> std::result::Result<TryParse<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct NumericType(PhantomData<fn() -> TryParse<u64>>);

    impl Visitor<'_> for NumericType {
        type Value = TryParse<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("A NumericType that can be reasonably coerced into a u64")
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(TryParse::Parsed(value))
        }

        fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_finite() && value >= 0.0 && value < (u64::MAX as f64) {
                Ok(TryParse::Parsed(value.round() as u64))
            } else {
                Err(serde::de::Error::custom("NumericType must be representable as a u64"))
            }
        }
    }

    match deserializer.deserialize_any(NumericType(PhantomData)) {
        Ok(ok) => Ok(ok),
        Err(_) => Ok(TryParse::FailedToParse),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::Algorithm;
    use crate::errors::ErrorKind;

    use super::{ClaimsForValidation, Validation, get_current_timestamp, validate};

    fn deserialize_claims(claims: &serde_json::Value) -> ClaimsForValidation<'_> {
        serde::Deserialize::deserialize(claims).unwrap()
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_in_future_ok() {
        let claims = json!({ "exp": get_current_timestamp() + 10000 });
        let res = validate(
            deserialize_claims(&claims),
            &Validation::new().with_algorithm(Algorithm::HS256),
        );
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_in_future_but_in_rejection_period_fails() {
        let claims = json!({ "exp": get_current_timestamp() + 500 });
        let mut validation = Validation::new().with_algorithm(Algorithm::HS256);
        validation.leeway = 0;
        validation.reject_tokens_expiring_in_less_than = 501;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_float_in_future_ok() {
        let claims = json!({ "exp": (get_current_timestamp() as f64) + 10000.123 });
        let res = validate(
            deserialize_claims(&claims),
            &Validation::new().with_algorithm(Algorithm::HS256),
        );
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_float_in_future_but_in_rejection_period_fails() {
        let claims = json!({ "exp": (get_current_timestamp() as f64) + 500.123 });
        let mut validation = Validation::new().with_algorithm(Algorithm::HS256);
        validation.leeway = 0;
        validation.reject_tokens_expiring_in_less_than = 501;
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_in_past_fails() {
        let claims = json!({ "exp": get_current_timestamp() - 100000 });
        let res = validate(
            deserialize_claims(&claims),
            &Validation::new().with_algorithm(Algorithm::HS256),
        );
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_float_in_past_fails() {
        let claims = json!({ "exp": (get_current_timestamp() as f64) - 100000.1234 });
        let res = validate(
            deserialize_claims(&claims),
            &Validation::new().with_algorithm(Algorithm::HS256),
        );
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_in_past_but_in_leeway_ok() {
        let claims = json!({ "exp": get_current_timestamp() - 500 });
        let validation = Validation::new().with_algorithm(Algorithm::HS256).with_leeway(1000 * 60);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    #[wasm_bindgen_test]
    fn validate_required_fields_are_present() {
        // TODO: I removed aud, iss, sub as new api only requires and validates them
        // if the user uses with_audience, with_issuer or with_subject
        // for spec_claim in ["exp", "nbf", "aud", "iss", "sub"] {
        let claims = json!({});
        let validation = Validation::new().with_exp(true, false);
        let res = validate(deserialize_claims(&claims), &validation).unwrap_err();
        assert_eq!(res.kind(), &ErrorKind::MissingRequiredClaim("exp".to_owned()));

        let claims = json!({});
        let validation = Validation::new().with_exp(false, false).with_nbf(true, false);
        let res = validate(deserialize_claims(&claims), &validation).unwrap_err();
        assert_eq!(res.kind(), &ErrorKind::MissingRequiredClaim("nbf".to_owned()));
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_validated_but_not_required_ok() {
        let claims = json!({});
        let validation = Validation::new().with_exp(false, true);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_validated_but_not_required_fails() {
        let claims = json!({ "exp": (get_current_timestamp() as f64) - 100000.1234 });
        let validation = Validation::new().with_exp(false, true);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_required_but_not_validated_ok() {
        let claims = json!({ "exp": (get_current_timestamp() as f64) - 100000.1234 });
        let validation = Validation::new().with_exp(true, false);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn exp_required_but_not_validated_fails() {
        let claims = json!({});
        let validation = Validation::new().with_exp(true, false);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());
    }

    #[test]
    #[wasm_bindgen_test]
    fn nbf_in_past_ok() {
        let claims = json!({ "nbf": get_current_timestamp() - 10000 });
        let validation = Validation::new().with_exp(false, false).with_nbf(false, true);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn nbf_float_in_past_ok() {
        let claims = json!({ "nbf": (get_current_timestamp() as f64) - 10000.1234 });
        let validation = Validation::new().with_exp(false, false).with_nbf(true, true);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn nbf_in_future_fails() {
        let claims = json!({ "nbf": get_current_timestamp() + 100000 });
        let validation = Validation::new().with_exp(false, false).with_nbf(false, true);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::ImmatureSignature => (),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn nbf_in_future_but_in_leeway_ok() {
        let claims = json!({ "nbf": get_current_timestamp() + 500 });
        let validation =
            Validation::new().with_exp(false, false).with_nbf(false, true).with_leeway(1000 * 60);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn iss_string_ok() {
        let claims = json!({"iss": ["Keats"]});
        let validation = Validation::new().with_exp(false, false).with_issuer(&["Keats"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn iss_array_of_string_ok() {
        let claims = json!({"iss": ["UserA", "UserB"]});
        let validation = Validation::new().with_exp(false, false).with_issuer(&["UserA", "UserB"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn iss_not_matching_fails() {
        let claims = json!({"iss": "Hacked"});

        let validation = Validation::new().with_exp(false, false).with_issuer(&["Keats"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidIssuer => (),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn iss_missing_fails() {
        let claims = json!({});

        let validation = Validation::new().with_exp(false, false).with_issuer(&["Keats"]);
        let res = validate(deserialize_claims(&claims), &validation);

        match res.unwrap_err().kind() {
            ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "iss"),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn sub_ok() {
        let claims = json!({"sub": "Keats"});
        let validation = Validation::new().with_exp(false, false).with_subject("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn sub_not_matching_fails() {
        let claims = json!({"sub": "Hacked"});
        let validation = Validation::new().with_exp(false, false).with_subject("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::InvalidSubject => (),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn sub_missing_fails() {
        let claims = json!({});
        let validation = Validation::new().with_exp(false, false).with_subject("Keats".to_owned());
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "sub"),
            _ => unreachable!(),
        };
    }

    #[test]
    #[wasm_bindgen_test]
    fn aud_string_ok() {
        let claims = json!({"aud": "Everyone"});
        let validation = Validation::new().with_exp(false, false).with_audience(&["Everyone"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn aud_array_of_string_ok() {
        let claims = json!({"aud": ["UserA", "UserB"]});
        let validation =
            Validation::new().with_exp(false, false).with_audience(&["UserA", "UserB"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn aud_type_mismatch_fails() {
        let claims = json!({"aud": ["Everyone"]});
        let validation =
            Validation::new().with_exp(false, false).with_audience(&["UserA", "UserB"]);
        let res = validate(deserialize_claims(&claims), &validation);

        assert_eq!(&ErrorKind::InvalidAudience, res.expect_err("error expected").kind());
    }

    #[test]
    #[wasm_bindgen_test]
    fn aud_correct_type_not_matching_fails() {
        let claims = json!({"aud": ["Everyone"]});
        let validation = Validation::new().with_exp(false, false).with_audience(&["None"]);
        let res = validate(deserialize_claims(&claims), &validation);

        assert_eq!(&ErrorKind::InvalidAudience, res.expect_err("error expected").kind());
    }

    // TODO: this is no longer desired behaviour, audience should be required and validated only when the user calls .with_audience(...)
    // #[test]
    // #[wasm_bindgen_test]
    // fn aud_none_fails() {
    //     let claims = json!({"aud": ["Everyone"]});
    //     let validation = Validation::new().with_exp(false, false);
    //     let res = validate(deserialize_claims(&claims), &validation);
    //     assert!(res.is_err());

    //     match res.unwrap_err().kind() {
    //         ErrorKind::InvalidAudience => (),
    //         _ => unreachable!(),
    //     };
    // }

    #[test]
    #[wasm_bindgen_test]
    fn aud_validation_skipped() {
        let claims = json!({"aud": ["Everyone"]});
        let validation = Validation::new().with_exp(false, false);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn aud_missing_fails() {
        let claims = json!({});
        let validation = Validation::new().with_exp(false, false).with_audience(&["None"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "aud"),
            _ => unreachable!(),
        };
    }

    // TODO: this is now the same as above
    // #[test]
    // #[wasm_bindgen_test]
    // fn set_audience_missing_fails() {
    //     let claims = json!({});
    //     let validation = Validation::new().with_exp(false, false).with_audience(&["None"]);
    //     let res = validate(deserialize_claims(&claims), &validation);
    //     assert!(res.is_err());

    //     match res.unwrap_err().kind() {
    //         ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "aud"),
    //         _ => unreachable!(),
    //     };
    // }

    #[test]
    #[wasm_bindgen_test]
    fn set_issuer_missing_fails() {
        let claims = json!({});
        let validation = Validation::new().with_exp(false, false).with_issuer(&["None"]);
        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());

        match res.unwrap_err().kind() {
            ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "iss"),
            _ => unreachable!(),
        };
    }

    // https://github.com/Keats/jsonwebtoken/issues/51
    #[test]
    #[wasm_bindgen_test]
    fn does_validation_in_right_order() {
        let claims = json!({ "exp": get_current_timestamp() + 10000 });

        let validation = Validation::new().with_issuer(&["iss no check"]).with_leeway(5);

        let res = validate(deserialize_claims(&claims), &validation);
        // It errors because it needs to validate iss/sub which are missing
        assert!(res.is_err());
        match res.unwrap_err().kind() {
            ErrorKind::MissingRequiredClaim(claim) => assert_eq!(claim, "iss"),
            t => panic!("{:?}", t),
        };
    }

    // TODO: I think this test is outdated? What is aud_hashset used for?
    // // https://github.com/Keats/jsonwebtoken/issues/110
    // #[test]
    // #[wasm_bindgen_test]
    // fn aud_use_validation_struct() {
    //     let claims = json!({"aud": "my-googleclientid1234.apps.googleusercontent.com"});

    //     let aud = "my-googleclientid1234.apps.googleusercontent.com".to_string();
    //     let mut aud_hashset = std::collections::HashSet::new();
    //     aud_hashset.insert(aud);
    //     let mut validation = Validation::new().with_algorithm(Algorithm::HS256);
    //     validation.validate_exp = false;
    //     validation.required_spec_claims = HashSet::new();
    //     validation.set_audience(&["my-googleclientid1234.apps.googleusercontent.com"]);

    //     let res = validate(deserialize_claims(&claims), &validation);
    //     assert!(res.is_ok());
    // }

    // https://github.com/Keats/jsonwebtoken/issues/388
    #[test]
    #[wasm_bindgen_test]
    fn doesnt_panic_with_leeway_overflow() {
        let claims = json!({ "exp": 1 });

        let validation = Validation::new().with_reject_tokens_expiring_in_less_than(100);

        let res = validate(deserialize_claims(&claims), &validation);
        assert!(res.is_err());
    }
}

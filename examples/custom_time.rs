use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

const SECRET: &str = "some-secret";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
}

impl Claims {
    /// If a token should always be equal to its representation after serializing and deserializing
    /// again, this function must be used for construction. `OffsetDateTime` contains a microsecond
    /// field but JWT timestamps are defined as UNIX timestamps (seconds). This function normalizes
    /// the timestamps.
    pub fn new(sub: String, iat: OffsetDateTime, exp: OffsetDateTime) -> Self {
        // normalize the timestamps by stripping of microseconds
        let iat = iat
            .date()
            .with_hms_milli(iat.hour(), iat.minute(), iat.second(), 0)
            .unwrap()
            .assume_utc();
        let exp = exp
            .date()
            .with_hms_milli(exp.hour(), exp.minute(), exp.second(), 0)
            .unwrap()
            .assume_utc();

        Self { sub, iat, exp }
    }
}

mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }

    #[cfg(test)]
    mod tests {
        const EXPECTED_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDdXN0b20gT2Zmc2V0RGF0ZVRpbWUgc2VyL2RlIiwiaWF0IjowLCJleHAiOjMyNTAzNjgwMDAwfQ.BcPipupP9oIV6uFRI6Acn7FMLws_wA3oo6CrfeFF3Gg";

        use super::super::{Claims, SECRET};
        use jsonwebtoken::{
            decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
        };
        use time::{Duration, OffsetDateTime};

        #[test]
        fn round_trip() {
            let sub = "Custom OffsetDateTime ser/de".to_string();
            let iat = OffsetDateTime::from_unix_timestamp(0).unwrap();
            let exp = OffsetDateTime::from_unix_timestamp(32503680000).unwrap();

            let claims = Claims::new(sub.clone(), iat, exp);

            let token =
                encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET.as_ref()))
                    .expect("Failed to encode claims");

            assert_eq!(&token, EXPECTED_TOKEN);

            let decoded = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(SECRET.as_ref()),
                &Validation::new(Algorithm::HS256),
            )
            .expect("Failed to decode token");

            assert_eq!(decoded.claims, claims);
        }

        #[test]
        fn should_fail_on_invalid_timestamp() {
            // A token with the expiry of i64::MAX + 1
            let overflow_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDdXN0b20gRGF0ZVRpbWUgc2VyL2RlIiwiaWF0IjowLCJleHAiOjkyMjMzNzIwMzY4NTQ3NzYwMDB9.G2PKreA27U8_xOwuIeCYXacFYeR46f9FyENIZfCrvEc";

            let decode_result = decode::<Claims>(
                &overflow_token,
                &DecodingKey::from_secret(SECRET.as_ref()),
                &Validation::new(Algorithm::HS256),
            );

            assert!(decode_result.is_err());
        }

        #[test]
        fn to_token_and_parse_equals_identity() {
            let iat = OffsetDateTime::now_utc();
            let exp = iat + Duration::days(1);
            let sub = "Custom OffsetDateTime ser/de".to_string();

            let claims = Claims::new(sub.clone(), iat, exp);

            let token =
                encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET.as_ref()))
                    .expect("Failed to encode claims");

            let decoded = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(SECRET.as_ref()),
                &Validation::new(Algorithm::HS256),
            )
            .expect("Failed to decode token")
            .claims;

            assert_eq!(claims, decoded);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sub = "Custom OffsetDateTime ser/de".to_string();
    let iat = OffsetDateTime::now_utc();
    let exp = iat + Duration::days(1);

    let claims = Claims::new(sub, iat, exp);

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_ref()),
    )?;

    println!("serialized token: {}", &token);

    let token_data = jsonwebtoken::decode::<Claims>(
        &token,
        &DecodingKey::from_secret(SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    )?;

    println!("token data:\n{:#?}", &token_data);
    Ok(())
}

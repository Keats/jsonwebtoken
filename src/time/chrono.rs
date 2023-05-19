use crate::decoding::DecodingOptions;
use crate::time::JwtInstant;
use chrono::{DateTime, TimeZone};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt::Formatter;

/// Deserializes [`chrono::DateTime`] from a UNIX timestamp or an RFC3339 timestamp.
pub struct ChronoDateTimeUtcUnixTimestampOrRFC3339(chrono::DateTime<chrono::UTC>);

struct SerdeChronoDateTimeUtcAsSecondsVisitor;

impl<'de> Visitor<'de> for SerdeChronoDateTimeUtcAsSecondsVisitor {
    type Value = ChronoDateTimeUtcUnixTimestampOrRFC3339;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str(
            "an integer or float representing a unix timestamp, or an RFC3339 timestamp string",
        )
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(ChronoDateTimeUtcUnixTimestampOrRFC3339(chrono::UTC.timestamp(v, 0)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(ChronoDateTimeUtcUnixTimestampOrRFC3339(chrono::UTC.timestamp(v as i64, 0)))
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let duration = std::time::Duration::from_secs_f32(v);
        Ok(ChronoDateTimeUtcUnixTimestampOrRFC3339(
            chrono::UTC.timestamp(duration.as_secs() as i64, duration.subsec_nanos()),
        ))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let duration = std::time::Duration::from_secs_f64(v);
        Ok(ChronoDateTimeUtcUnixTimestampOrRFC3339(
            chrono::UTC.timestamp(duration.as_secs() as i64, duration.subsec_nanos()),
        ))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match chrono::DateTime::parse_from_rfc3339(v) {
            Ok(t) => Ok(ChronoDateTimeUtcUnixTimestampOrRFC3339(t.with_timezone(&chrono::UTC))),
            Err(err) => Err(E::custom("Invalid timestamp format")),
        }
    }
}

impl<'de> Deserialize<'de> for ChronoDateTimeUtcUnixTimestampOrRFC3339 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SerdeChronoDateTimeUtcAsSecondsVisitor)
    }
}

impl<'a> From<&'a ChronoDateTimeUtcUnixTimestampOrRFC3339> for chrono::DateTime<chrono::UTC> {
    fn from(value: &'a ChronoDateTimeUtcUnixTimestampOrRFC3339) -> Self {
        value.0
    }
}

impl JwtInstant for chrono::DateTime<chrono::UTC> {
    fn now() -> Self {
        chrono::UTC::now()
    }

    fn is_before(&self, other: &Self) -> bool {
        *self < *other
    }

    fn is_after(&self, other: &Self) -> bool {
        *self > *other
    }

    fn with_added_seconds(&self, seconds: u64) -> Self {
        *self + chrono::Duration::seconds(seconds as i64)
    }
}

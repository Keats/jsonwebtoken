use crate::time::JwtInstant;
use chrono::TimeZone;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt::Formatter;

/// Deserializes [`chrono::DateTime`] from a UNIX timestamp
pub struct ChronoDateTimeUtcUnixTimestamp(chrono::DateTime<chrono::UTC>);

struct SerdeChronoDateTimeUtcAsSecondsVisitor;

impl<'de> Visitor<'de> for SerdeChronoDateTimeUtcAsSecondsVisitor {
    type Value = ChronoDateTimeUtcUnixTimestamp;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("an integer or float representing a unix timestamp")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(ChronoDateTimeUtcUnixTimestamp(chrono::UTC.timestamp(v as i64, 0)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let duration = std::time::Duration::from_secs_f64(v);
        Ok(ChronoDateTimeUtcUnixTimestamp(
            chrono::UTC.timestamp(duration.as_secs() as i64, duration.subsec_nanos()),
        ))
    }
}

impl<'de> Deserialize<'de> for ChronoDateTimeUtcUnixTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SerdeChronoDateTimeUtcAsSecondsVisitor)
    }
}

impl<'a> From<&'a ChronoDateTimeUtcUnixTimestamp> for chrono::DateTime<chrono::UTC> {
    fn from(value: &'a ChronoDateTimeUtcUnixTimestamp) -> Self {
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

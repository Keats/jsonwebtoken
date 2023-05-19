use crate::decoding::DecodingOptions;
use crate::time::JwtInstant;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt::Formatter;
use time::OffsetDateTime;

/// Deserializes [`time::OffsetDateTime`] from a UNIX timestamp
pub struct SerdeTimeOffsetTimeAsSeconds(OffsetDateTime);

struct SerdeTimeOffsetTimeAsSecondsVisitor;

impl<'de> Visitor<'de> for SerdeTimeOffsetTimeAsSecondsVisitor {
    type Value = SerdeTimeOffsetTimeAsSeconds;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str(
            "an integer or float representing a unix timestamp, or an ISO timestamp string",
        )
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Ok(t) = OffsetDateTime::from_unix_timestamp(v) {
            return Ok(SerdeTimeOffsetTimeAsSeconds(t));
        } else {
            return Err(E::custom("Couldn't unix timestamp to OffsetDateTime"));
        }
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Ok(t) = OffsetDateTime::from_unix_timestamp(v as i64) {
            return Ok(SerdeTimeOffsetTimeAsSeconds(t));
        } else {
            return Err(E::custom("Couldn't unix timestamp to OffsetDateTime"));
        }
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Ok(t) = OffsetDateTime::from_unix_timestamp_nanos(
            std::time::Duration::from_secs_f32(v).as_nanos() as i128,
        ) {
            return Ok(SerdeTimeOffsetTimeAsSeconds(t));
        } else {
            return Err(E::custom("Couldn't unix timestamp to OffsetDateTime"));
        }
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Ok(t) = OffsetDateTime::from_unix_timestamp_nanos(
            std::time::Duration::from_secs_f64(v).as_nanos() as i128,
        ) {
            return Ok(SerdeTimeOffsetTimeAsSeconds(t));
        } else {
            return Err(E::custom("Couldn't unix timestamp to OffsetDateTime"));
        }
    }
}

impl<'de> Deserialize<'de> for SerdeTimeOffsetTimeAsSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SerdeTimeOffsetTimeAsSecondsVisitor)
    }
}

impl<'a> From<&'a SerdeTimeOffsetTimeAsSeconds> for OffsetDateTime {
    fn from(value: &'a SerdeTimeOffsetTimeAsSeconds) -> Self {
        value.0
    }
}

impl JwtInstant for OffsetDateTime {
    fn now() -> Self {
        OffsetDateTime::now_utc()
    }

    fn is_before(&self, other: &Self) -> bool {
        *self < *other
    }

    fn is_after(&self, other: &Self) -> bool {
        *self > *other
    }

    fn with_added_seconds(&self, seconds: u64) -> Self {
        *self + time::Duration::seconds(seconds as i64)
    }
}

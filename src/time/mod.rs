#[cfg(feature = "time")]
mod time_crate;

#[cfg(feature = "time")]
pub use self::time_crate::SerdeTimeOffsetTimeAsSeconds;

#[cfg(feature = "chrono")]
mod chrono;

#[cfg(feature = "chrono")]
pub use self::chrono::ChronoDateTimeUtcUnixTimestampOrRFC3339;

use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Formatter;
use std::time::{Duration, SystemTime};

/// Trait for getting the current time and comparing various JWT timestamps.
pub trait JwtInstant: Sized {
    /// Returns an instant corresponding to the current time.
    fn now() -> Self;

    /// Checks if the current instant is before the given instant.
    fn is_before(&self, other: &Self) -> bool;

    /// Checks if the current instant is after the given instant.
    fn is_after(&self, other: &Self) -> bool;

    /// Returns a new instant by adding the specified number of seconds to the current instant.
    fn with_added_seconds(&self, seconds: u64) -> Self;
}

/// Deserializes [`std::time::SystemTime`] from a UNIX timestamp.
///
/// # Warning
///
/// This implementation assumes that the server's timezone is set to UTC. If your server's timezone
/// is different, consider enabling and using the `time` or `chrono` features in this crate, which
/// provide more comprehensive timezone handling.
pub struct SerdeSystemTimeFromSeconds(SystemTime);

struct SerdeSystemTimeAsSecondsVisitor;

impl<'de> Visitor<'de> for SerdeSystemTimeAsSecondsVisitor {
    type Value = SerdeSystemTimeFromSeconds;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("an integer or float representing a unix timestamp")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(SerdeSystemTimeFromSeconds(SystemTime::UNIX_EPOCH + Duration::from_secs(v)))
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(SerdeSystemTimeFromSeconds(SystemTime::UNIX_EPOCH + Duration::from_secs_f32(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(SerdeSystemTimeFromSeconds(SystemTime::UNIX_EPOCH + Duration::from_secs_f64(v)))
    }
}

impl<'de> Deserialize<'de> for SerdeSystemTimeFromSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SerdeSystemTimeAsSecondsVisitor)
    }
}

impl<'a> From<&'a SerdeSystemTimeFromSeconds> for SystemTime {
    fn from(value: &'a SerdeSystemTimeFromSeconds) -> Self {
        value.0
    }
}

impl JwtInstant for SystemTime {
    fn now() -> Self {
        SystemTime::now()
    }

    fn is_before(&self, other: &Self) -> bool {
        *self < *other
    }

    fn is_after(&self, other: &Self) -> bool {
        *self > *other
    }

    fn with_added_seconds(&self, seconds: u64) -> Self {
        *self + Duration::from_secs(seconds)
    }
}

/// Specifies the types used for deserializing and comparing timestamps found in the JWTs
pub trait TimestampOptions {
    /// The type used to represent and compare timestamps
    type Instant: JwtInstant + for<'a> From<&'a Self::InstantDeserializationWrapper>;
    /// The type used to deserialize the timestamps from JSON
    type InstantDeserializationWrapper: for<'de> Deserialize<'de>;
}

/// Uses [`std::time::SystemTime`] to to represent timestamps.
#[cfg(not(any(feature = "default_time", feature = "default_chrono")))]
pub type DefaultTimestampOptions = DefaultSystemTimeTimestampOptions;

/// Uses [`::time::OffsetDateTime`] to to represent timestamps.
#[cfg(feature = "default_time")]
pub type DefaultTimestampOptions = TimeOffsetDateTimeTimestampOptions;

/// Uses [`::chrono::DateTime::<::chrono::UTC>`] to to represent timestamps.
#[cfg(feature = "default_chrono")]
pub type DefaultTimestampOptions = ChronoDateTimeUtcTimestampOptions;

/// Uses [`std::time::SystemTime`] to to represent timestamps.
#[derive(Default)]
pub struct DefaultSystemTimeTimestampOptions;

impl TimestampOptions for DefaultSystemTimeTimestampOptions {
    type Instant = SystemTime;
    type InstantDeserializationWrapper = SerdeSystemTimeFromSeconds;
}

/// Uses [`time::OffsetDateTime`] to to represent timestamps.
#[cfg(feature = "time")]
#[derive(Default)]
pub struct TimeOffsetDateTimeTimestampOptions;

#[cfg(feature = "time")]
impl TimestampOptions for TimeOffsetDateTimeTimestampOptions {
    type Instant = time::OffsetDateTime;
    type InstantDeserializationWrapper = crate::time::SerdeTimeOffsetTimeAsSeconds;
}

/// Uses [`chrono::DateTime::<chrono::UTC>`] to to represent timestamps.
#[cfg(feature = "chrono")]
#[derive(Default)]
pub struct ChronoDateTimeUtcTimestampOptions;

#[cfg(feature = "chrono")]
impl TimestampOptions for ChronoDateTimeUtcTimestampOptions {
    type Instant = ::chrono::DateTime<::chrono::UTC>;
    type InstantDeserializationWrapper = crate::time::ChronoDateTimeUtcUnixTimestampOrRFC3339;
}

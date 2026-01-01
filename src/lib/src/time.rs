//! Time validation for offline-first verification
//!
//! This module provides time source abstraction for embedded and edge devices
//! that may not have reliable system clocks. It supports multiple strategies:
//!
//! # Design Principle
//! **"Trust Rekor time for validity, user provides time for freshness"**
//!
//! - **Rekor `integrated_time`**: A trusted timestamp signed in the SET (Signed Entry Timestamp).
//!   This is used for certificate validity checks without needing system time.
//! - **Build-time constant**: Provides a guaranteed minimum time (the code can't exist before
//!   it was compiled). Useful as a lower bound for embedded devices.
//! - **User-provided time**: For freshness checks, the verifier can provide their own time
//!   source (RTC, NTP, GPS, etc.).
//!
//! # Usage
//!
//! ```rust,ignore
//! use wsc::time::{TimeSource, SystemTimeSource, BuildTimeSource, FixedTimeSource};
//!
//! // Use system time (default for development/testing)
//! let system = SystemTimeSource;
//! let now = system.now()?;
//!
//! // Use build time as minimum (for embedded devices)
//! let build = BuildTimeSource;
//! let minimum = build.minimum_time();
//!
//! // Use a fixed time (for testing or known-good timestamps)
//! let fixed = FixedTimeSource::from_unix_secs(1704067200)?; // 2024-01-01 00:00:00 UTC
//! ```
//!
//! # Security Considerations
//!
//! For keyless signature verification:
//! 1. **Certificate validity**: Always checked against Rekor's `integrated_time`, which is
//!    cryptographically bound to the signature. No system time needed.
//! 2. **Freshness checks**: Optional, require a trusted time source. Embedded devices should
//!    use RTC, GPS, or other reliable time sources if freshness is required.
//! 3. **Build-time lower bound**: Even without a clock, we know the current time is at least
//!    when the binary was compiled.

use crate::error::WSError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Build timestamp set at compile time.
///
/// This is the Unix timestamp (seconds since 1970-01-01) when the library was compiled.
/// It provides a guaranteed lower bound for time validation on embedded devices.
///
/// On platforms without `build.rs` support, falls back to a reasonable default.
pub const BUILD_TIMESTAMP: u64 = {
    // Try to parse from environment variable set by build.rs
    // If not available, use a hardcoded fallback that should be updated on release
    match option_env!("WSC_BUILD_TIMESTAMP") {
        Some(s) => {
            // Parse the string to u64 at compile time
            // This is a simple parser since const fn is limited
            let bytes = s.as_bytes();
            let mut result: u64 = 0;
            let mut i = 0;
            while i < bytes.len() {
                let digit = bytes[i] as u64 - b'0' as u64;
                result = result * 10 + digit;
                i += 1;
            }
            result
        }
        // Fallback: 2024-01-01 00:00:00 UTC
        // This should be updated with each release
        None => 1704067200,
    }
};

/// Time source abstraction for pluggable time providers
///
/// This trait allows embedded devices to provide their own time source
/// (RTC, GPS, NTP, etc.) for signature freshness checks.
///
/// # Implementors
///
/// - [`SystemTimeSource`]: Uses `std::time::SystemTime` (default for development)
/// - [`BuildTimeSource`]: Returns only build time as minimum (no current time)
/// - [`FixedTimeSource`]: Returns a fixed timestamp (for testing)
///
/// # Example Implementation
///
/// ```rust,ignore
/// use wsc::time::{TimeSource, BUILD_TIMESTAMP};
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// struct RtcTimeSource {
///     rtc: embedded_hal::rtc::Rtc,
/// }
///
/// impl TimeSource for RtcTimeSource {
///     fn now(&self) -> Result<SystemTime, WSError> {
///         let secs = self.rtc.get_datetime()?.timestamp() as u64;
///         Ok(UNIX_EPOCH + Duration::from_secs(secs))
///     }
///
///     fn minimum_time(&self) -> SystemTime {
///         UNIX_EPOCH + Duration::from_secs(BUILD_TIMESTAMP)
///     }
///
///     fn is_reliable(&self) -> bool {
///         self.rtc.is_initialized()
///     }
/// }
/// ```
pub trait TimeSource: Send + Sync {
    /// Get the current time from this source.
    ///
    /// Returns an error if time cannot be determined (e.g., RTC not initialized).
    fn now(&self) -> Result<SystemTime, WSError>;

    /// Get the minimum possible time (lower bound).
    ///
    /// This is used as a sanity check - any timestamp before this is invalid.
    /// Typically returns the build time of the binary.
    fn minimum_time(&self) -> SystemTime;

    /// Check if this time source is considered reliable.
    ///
    /// An unreliable time source (e.g., uninitialized RTC) should only be used
    /// for minimum bounds, not for freshness checks.
    fn is_reliable(&self) -> bool;

    /// Get current time as Unix timestamp (seconds since epoch).
    fn now_unix(&self) -> Result<u64, WSError> {
        let time = self.now()?;
        Ok(time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs())
    }

    /// Get minimum time as Unix timestamp.
    fn minimum_unix(&self) -> u64 {
        self.minimum_time()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// System time source using `std::time::SystemTime`
///
/// This is the default time source for development and testing environments
/// where the system clock is trusted. On embedded devices, prefer using
/// [`BuildTimeSource`] or a custom implementation with RTC/GPS.
///
/// # Reliability
///
/// Always reports as reliable since `SystemTime::now()` should succeed
/// on platforms with `std`. However, the system clock may be wrong if
/// not synced with NTP.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> Result<SystemTime, WSError> {
        Ok(SystemTime::now())
    }

    fn minimum_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(BUILD_TIMESTAMP)
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

/// Build-time-only time source
///
/// This source only provides a minimum time (the build timestamp) and does
/// not provide current time. It's useful for embedded devices without a
/// reliable clock that still want basic time validation.
///
/// # Usage
///
/// When used with keyless verification:
/// - Certificate validity is checked against Rekor's `integrated_time` (no system time needed)
/// - Freshness checks are skipped (freshness requires user-provided time)
/// - Build time ensures signatures can't be from before the binary was compiled
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildTimeSource;

impl TimeSource for BuildTimeSource {
    fn now(&self) -> Result<SystemTime, WSError> {
        Err(WSError::TimeError(
            "BuildTimeSource does not provide current time - use Rekor integrated_time for verification".to_string()
        ))
    }

    fn minimum_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(BUILD_TIMESTAMP)
    }

    fn is_reliable(&self) -> bool {
        false
    }
}

/// Fixed time source for testing
///
/// Returns a predetermined timestamp, useful for:
/// - Unit testing with reproducible time
/// - Replaying verification at a known point in time
/// - Debugging time-related verification failures
#[derive(Debug, Clone, Copy)]
pub struct FixedTimeSource {
    timestamp: SystemTime,
}

impl FixedTimeSource {
    /// Create from a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp is before the build time.
    pub fn from_unix_secs(secs: u64) -> Result<Self, WSError> {
        if secs < BUILD_TIMESTAMP {
            return Err(WSError::TimeError(format!(
                "Timestamp {} is before build time {}",
                secs, BUILD_TIMESTAMP
            )));
        }
        Ok(Self {
            timestamp: UNIX_EPOCH + Duration::from_secs(secs),
        })
    }

    /// Create from a `SystemTime`.
    ///
    /// # Errors
    ///
    /// Returns an error if the time is before the build time.
    pub fn from_system_time(time: SystemTime) -> Result<Self, WSError> {
        let secs = time
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WSError::TimeError(format!("Time before Unix epoch: {}", e)))?
            .as_secs();
        Self::from_unix_secs(secs)
    }

    /// Get the fixed timestamp.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }
}

impl TimeSource for FixedTimeSource {
    fn now(&self) -> Result<SystemTime, WSError> {
        Ok(self.timestamp)
    }

    fn minimum_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(BUILD_TIMESTAMP)
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

/// Time validation configuration for keyless verification
///
/// Controls how time is validated during signature verification.
pub struct TimeValidationConfig {
    /// Time source for freshness checks (None = skip freshness checks)
    pub time_source: Option<Box<dyn TimeSource>>,

    /// Maximum age for signatures (None = no maximum)
    ///
    /// Signatures older than this are rejected even if otherwise valid.
    /// This is useful for enforcing signature freshness policies.
    pub max_signature_age: Option<Duration>,

    /// Minimum time offset to account for clock skew (default: 5 minutes)
    ///
    /// Signatures timestamped slightly in the future (within this offset)
    /// are accepted to account for clock synchronization issues.
    pub clock_skew_tolerance: Duration,
}

impl std::fmt::Debug for TimeValidationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeValidationConfig")
            .field("time_source", &self.time_source.as_ref().map(|_| "<TimeSource>"))
            .field("max_signature_age", &self.max_signature_age)
            .field("clock_skew_tolerance", &self.clock_skew_tolerance)
            .finish()
    }
}

impl Default for TimeValidationConfig {
    fn default() -> Self {
        Self {
            time_source: None,
            max_signature_age: None,
            clock_skew_tolerance: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl TimeValidationConfig {
    /// Create configuration that skips freshness checks.
    ///
    /// Certificate validity is still checked against Rekor's integrated_time.
    pub fn no_freshness() -> Self {
        Self::default()
    }

    /// Create configuration using system time for freshness checks.
    pub fn with_system_time() -> Self {
        Self {
            time_source: Some(Box::new(SystemTimeSource)),
            ..Default::default()
        }
    }

    /// Create configuration with a custom time source.
    pub fn with_time_source(source: impl TimeSource + 'static) -> Self {
        Self {
            time_source: Some(Box::new(source)),
            ..Default::default()
        }
    }

    /// Set maximum allowed signature age.
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_signature_age = Some(age);
        self
    }

    /// Set clock skew tolerance.
    pub fn clock_skew(mut self, tolerance: Duration) -> Self {
        self.clock_skew_tolerance = tolerance;
        self
    }
}

// We can't implement Clone on Box<dyn TimeSource>, but we need TimeValidationConfig to be usable
// in configuration structures. The time_source is optional and can be re-created if needed.
impl Clone for TimeValidationConfig {
    fn clone(&self) -> Self {
        Self {
            // Can't clone the time source, create a new one if system time was used
            time_source: None,
            max_signature_age: self.max_signature_age,
            clock_skew_tolerance: self.clock_skew_tolerance,
        }
    }
}

/// Validate a timestamp against time constraints.
///
/// # Arguments
///
/// * `timestamp_secs` - Unix timestamp to validate
/// * `config` - Time validation configuration
///
/// # Returns
///
/// * `Ok(true)` - Timestamp is valid
/// * `Ok(false)` - Timestamp fails validation (but not an error)
/// * `Err(_)` - Validation could not be performed
pub fn validate_timestamp(timestamp_secs: u64, config: &TimeValidationConfig) -> Result<bool, WSError> {
    // Check against minimum (build time)
    if timestamp_secs < BUILD_TIMESTAMP {
        log::warn!(
            "Timestamp {} is before build time {}",
            timestamp_secs,
            BUILD_TIMESTAMP
        );
        return Ok(false);
    }

    // If we have a time source, check freshness
    if let Some(ref time_source) = config.time_source {
        if time_source.is_reliable() {
            let now = time_source.now_unix()?;
            let skew = config.clock_skew_tolerance.as_secs();

            // Check for timestamps too far in the future
            if timestamp_secs > now + skew {
                log::warn!(
                    "Timestamp {} is {} seconds in the future (tolerance: {})",
                    timestamp_secs,
                    timestamp_secs - now,
                    skew
                );
                return Ok(false);
            }

            // Check maximum age if configured
            if let Some(max_age) = config.max_signature_age {
                let max_age_secs = max_age.as_secs();
                if now > timestamp_secs && now - timestamp_secs > max_age_secs {
                    log::warn!(
                        "Signature is {} seconds old (max age: {})",
                        now - timestamp_secs,
                        max_age_secs
                    );
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

/// Parse an ISO 8601 / RFC 3339 timestamp to Unix seconds.
///
/// Supports common formats:
/// - `2024-01-15T12:30:45Z` (UTC)
/// - `2024-01-15T12:30:45.123Z` (with milliseconds)
/// - `1705323045` (Unix timestamp as string)
pub fn parse_timestamp(timestamp: &str) -> Result<u64, WSError> {
    // Try parsing as Unix timestamp first
    if let Ok(secs) = timestamp.parse::<u64>() {
        return Ok(secs);
    }

    // Try parsing as ISO 8601 / RFC 3339
    // Format: YYYY-MM-DDTHH:MM:SS[.fraction]Z
    let timestamp = timestamp.trim();

    // Simple parser for common format
    if timestamp.len() >= 20 && timestamp.ends_with('Z') {
        // Parse: 2024-01-15T12:30:45Z or 2024-01-15T12:30:45.123Z
        let parts: Vec<&str> = timestamp[..19].split(|c| c == '-' || c == 'T' || c == ':').collect();
        if parts.len() == 6 {
            let year: i32 = parts[0].parse().map_err(|_| WSError::TimeError("Invalid year".into()))?;
            let month: u32 = parts[1].parse().map_err(|_| WSError::TimeError("Invalid month".into()))?;
            let day: u32 = parts[2].parse().map_err(|_| WSError::TimeError("Invalid day".into()))?;
            let hour: u32 = parts[3].parse().map_err(|_| WSError::TimeError("Invalid hour".into()))?;
            let minute: u32 = parts[4].parse().map_err(|_| WSError::TimeError("Invalid minute".into()))?;
            let second: u32 = parts[5].parse().map_err(|_| WSError::TimeError("Invalid second".into()))?;

            // Convert to Unix timestamp using simplified calculation
            // (accurate for dates 1970-2100)
            let days = days_since_epoch(year, month, day)?;
            let secs = (days as u64) * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64);
            return Ok(secs);
        }
    }

    Err(WSError::TimeError(format!(
        "Cannot parse timestamp: '{}'",
        timestamp
    )))
}

/// Calculate days since Unix epoch (1970-01-01)
fn days_since_epoch(year: i32, month: u32, day: u32) -> Result<i64, WSError> {
    if year < 1970 {
        return Err(WSError::TimeError("Year before 1970".into()));
    }
    if !(1..=12).contains(&month) {
        return Err(WSError::TimeError("Invalid month".into()));
    }
    if !(1..=31).contains(&day) {
        return Err(WSError::TimeError("Invalid day".into()));
    }

    // Days in months (non-leap year)
    const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);

    let mut days: i64 = 0;

    // Add days for complete years
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }

    // Add days for complete months in current year
    for m in 1..month {
        let d = DAYS_IN_MONTH[(m - 1) as usize];
        days += d as i64;
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }

    // Add days in current month
    days += (day - 1) as i64;

    Ok(days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timestamp_is_reasonable() {
        // Build timestamp should be after 2024-01-01
        assert!(BUILD_TIMESTAMP >= 1704067200);
        // And before 2100-01-01
        assert!(BUILD_TIMESTAMP < 4102444800);
    }

    #[test]
    fn test_system_time_source() {
        let source = SystemTimeSource;
        let now = source.now().unwrap();
        assert!(now > source.minimum_time());
        assert!(source.is_reliable());
    }

    #[test]
    fn test_build_time_source() {
        let source = BuildTimeSource;
        assert!(source.now().is_err());
        assert!(!source.is_reliable());
        assert!(source.minimum_unix() >= 1704067200);
    }

    #[test]
    fn test_fixed_time_source() {
        // Use a time after BUILD_TIMESTAMP
        let future_time = BUILD_TIMESTAMP + 86400; // 1 day after build
        let source = FixedTimeSource::from_unix_secs(future_time).unwrap();
        assert!(source.is_reliable());
        assert_eq!(source.now_unix().unwrap(), future_time);
    }

    #[test]
    fn test_fixed_time_source_rejects_old_time() {
        // Time before build should fail
        let result = FixedTimeSource::from_unix_secs(1000000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_timestamp_unix() {
        assert_eq!(parse_timestamp("1704067200").unwrap(), 1704067200);
    }

    #[test]
    fn test_parse_timestamp_iso8601() {
        // 2024-01-01 00:00:00 UTC
        assert_eq!(parse_timestamp("2024-01-01T00:00:00Z").unwrap(), 1704067200);

        // 2024-01-15 12:30:45 UTC
        let expected = 1704067200 + 14 * 86400 + 12 * 3600 + 30 * 60 + 45;
        assert_eq!(parse_timestamp("2024-01-15T12:30:45Z").unwrap(), expected);
    }

    #[test]
    fn test_parse_timestamp_with_millis() {
        // Should handle milliseconds (they're ignored)
        assert_eq!(
            parse_timestamp("2024-01-01T00:00:00.123Z").unwrap(),
            1704067200
        );
    }

    #[test]
    fn test_validate_timestamp_basic() {
        let config = TimeValidationConfig::no_freshness();

        // Future time is valid (no freshness check)
        let future = BUILD_TIMESTAMP + 86400 * 365; // 1 year after build
        assert!(validate_timestamp(future, &config).unwrap());

        // Old time before build is invalid
        assert!(!validate_timestamp(1000000000, &config).unwrap());
    }

    #[test]
    fn test_validate_timestamp_with_max_age() {
        let config = TimeValidationConfig::with_system_time()
            .max_age(Duration::from_secs(3600)); // 1 hour max age

        let now = SystemTimeSource.now_unix().unwrap();

        // Very old timestamp should fail (use BUILD_TIMESTAMP + a small offset if too old
        // would be before build time, otherwise use 2 hours ago)
        let old_time = if now > BUILD_TIMESTAMP + 7200 {
            now - 7200 // 2 hours ago
        } else {
            BUILD_TIMESTAMP // Use build time which is always > max_age from now
        };
        // Old time beyond max_age should fail
        let old_result = validate_timestamp(old_time, &config).unwrap();
        if now - old_time > 3600 {
            assert!(!old_result, "Timestamps older than max_age should fail");
        }

        // Recent timestamp should pass (use now - 30 min, but not before build time)
        let recent = std::cmp::max(now - 1800, BUILD_TIMESTAMP);
        // If recent is after build time and within max_age, it should pass
        if now - recent <= 3600 && recent >= BUILD_TIMESTAMP {
            assert!(validate_timestamp(recent, &config).unwrap());
        }
    }

    #[test]
    fn test_validate_timestamp_future_with_skew() {
        let config = TimeValidationConfig::with_system_time()
            .clock_skew(Duration::from_secs(300)); // 5 min tolerance

        let now = SystemTimeSource.now_unix().unwrap();

        // Slightly in future (within skew) should pass
        assert!(validate_timestamp(now + 60, &config).unwrap()); // 1 min ahead

        // Too far in future should fail
        assert!(!validate_timestamp(now + 600, &config).unwrap()); // 10 min ahead
    }

    #[test]
    fn test_time_validation_config_clone() {
        let config = TimeValidationConfig::with_system_time()
            .max_age(Duration::from_secs(3600))
            .clock_skew(Duration::from_secs(120));

        let cloned = config.clone();
        assert_eq!(cloned.max_signature_age, Some(Duration::from_secs(3600)));
        assert_eq!(cloned.clock_skew_tolerance, Duration::from_secs(120));
        // Note: time_source is not cloned (becomes None)
        assert!(cloned.time_source.is_none());
    }

    #[test]
    fn test_days_since_epoch() {
        // 1970-01-01 should be day 0
        assert_eq!(days_since_epoch(1970, 1, 1).unwrap(), 0);

        // 1970-01-02 should be day 1
        assert_eq!(days_since_epoch(1970, 1, 2).unwrap(), 1);

        // 2024-01-01 = 1704067200 / 86400 = 19723 days
        assert_eq!(days_since_epoch(2024, 1, 1).unwrap(), 19723);
    }
}

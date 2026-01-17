/// Rate limiting for Sigstore API endpoints
///
/// Prevents abuse and respects server-side limits for:
/// - Fulcio (certificate issuance)
/// - Rekor (transparency log)
/// - OIDC providers (token exchange)
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::error::WSError;

/// Sliding window rate limiter
///
/// Tracks requests within a time window and rejects new requests
/// when the limit is exceeded.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: usize,
    /// Time window duration
    window: Duration,
    /// Request timestamps (circular buffer)
    requests: VecDeque<Instant>,
    /// Name for error messages
    name: String,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `name` - Identifier for error messages (e.g., "Fulcio", "Rekor")
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window` - Time window duration
    pub fn new(name: impl Into<String>, max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            requests: VecDeque::with_capacity(max_requests + 1),
            name: name.into(),
        }
    }

    /// Check if a request is allowed under the rate limit
    ///
    /// Returns Ok(()) if allowed, or an error with retry duration if limited.
    pub fn check(&mut self) -> Result<(), WSError> {
        let now = Instant::now();

        // Remove old requests outside the window
        while let Some(&oldest) = self.requests.front() {
            if now.duration_since(oldest) > self.window {
                self.requests.pop_front();
            } else {
                break;
            }
        }

        // Check if we're at the limit
        if self.requests.len() >= self.max_requests {
            let oldest = self.requests.front().unwrap();
            let wait_time = self.window.saturating_sub(now.duration_since(*oldest));

            return Err(WSError::RateLimitExceeded {
                service: self.name.clone(),
                retry_after: wait_time,
            });
        }

        // Record this request
        self.requests.push_back(now);
        Ok(())
    }

    /// Get current request count in window
    pub fn current_count(&self) -> usize {
        self.requests.len()
    }

    /// Get remaining requests before limit
    pub fn remaining(&self) -> usize {
        self.max_requests.saturating_sub(self.requests.len())
    }
}

/// Retry policy with exponential backoff
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay (cap for exponential growth)
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Calculate delay for a given retry attempt (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let delay_secs = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32 - 1);
        let delay = Duration::from_secs_f64(delay_secs);

        std::cmp::min(delay, self.max_delay)
    }
}

/// Rate limit information from server headers
#[derive(Debug, Clone)]
pub struct ServerRateLimitInfo {
    /// Maximum requests allowed
    pub limit: Option<u64>,
    /// Remaining requests in current window
    pub remaining: Option<u64>,
    /// Unix timestamp when limit resets
    pub reset_at: Option<u64>,
    /// Seconds to wait before retrying (from Retry-After header)
    pub retry_after: Option<u64>,
}

impl ServerRateLimitInfo {
    /// Parse rate limit headers from HTTP response
    ///
    /// Supports standard headers:
    /// - X-RateLimit-Limit
    /// - X-RateLimit-Remaining
    /// - X-RateLimit-Reset
    /// - Retry-After
    pub fn from_headers<F>(get_header: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        Self {
            limit: get_header("X-RateLimit-Limit").and_then(|v| v.parse().ok()),
            remaining: get_header("X-RateLimit-Remaining").and_then(|v| v.parse().ok()),
            reset_at: get_header("X-RateLimit-Reset").and_then(|v| v.parse().ok()),
            retry_after: get_header("Retry-After").and_then(|v| v.parse().ok()),
        }
    }

    /// Check if we're rate limited (remaining = 0 or retry_after present)
    pub fn is_limited(&self) -> bool {
        self.remaining == Some(0) || self.retry_after.is_some()
    }

    /// Get recommended wait time
    pub fn wait_duration(&self) -> Option<Duration> {
        self.retry_after.map(Duration::from_secs)
    }
}

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Enable rate limiting (default: true)
    pub enabled: bool,
    /// Fulcio requests per minute (default: 10)
    pub fulcio_rpm: usize,
    /// Rekor requests per minute (default: 20)
    pub rekor_rpm: usize,
    /// OIDC requests per minute (default: 5)
    pub oidc_rpm: usize,
    /// Retry policy for failed requests
    pub retry_policy: RetryPolicy,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fulcio_rpm: 10,
            rekor_rpm: 20,
            oidc_rpm: 5,
            retry_policy: RetryPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new("test", 3, Duration::from_secs(1));

        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert_eq!(limiter.current_count(), 3);
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn test_rate_limiter_blocks_at_limit() {
        let mut limiter = RateLimiter::new("test", 2, Duration::from_secs(10));

        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());

        let result = limiter.check();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::RateLimitExceeded { .. }));
    }

    #[test]
    fn test_rate_limiter_resets_after_window() {
        let mut limiter = RateLimiter::new("test", 2, Duration::from_millis(50));

        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err());

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();

        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(4));
    }

    #[test]
    fn test_retry_policy_caps_at_max() {
        let policy = RetryPolicy {
            max_retries: 10,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
        };

        // Should cap at 5 seconds
        assert_eq!(policy.delay_for_attempt(10), Duration::from_secs(5));
    }

    #[test]
    fn test_server_rate_limit_info() {
        let info = ServerRateLimitInfo::from_headers(|name| match name {
            "X-RateLimit-Limit" => Some("100".to_string()),
            "X-RateLimit-Remaining" => Some("0".to_string()),
            "Retry-After" => Some("30".to_string()),
            _ => None,
        });

        assert_eq!(info.limit, Some(100));
        assert_eq!(info.remaining, Some(0));
        assert!(info.is_limited());
        assert_eq!(info.wait_duration(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();

        assert!(config.enabled);
        assert_eq!(config.fulcio_rpm, 10);
        assert_eq!(config.rekor_rpm, 20);
        assert_eq!(config.oidc_rpm, 5);
    }
}

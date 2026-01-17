/// Metrics collection for signature operations (Issue #3)
///
/// Provides observability for:
/// - Signing attempts and outcomes
/// - Validation attempts and failures
/// - Latency tracking
/// - Error categorization
///
/// Exports metrics in Prometheus exposition format.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Failure reasons for signing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningFailure {
    /// OIDC token invalid or expired
    TokenInvalid,
    /// Fulcio certificate issuance failed
    CertificateIssuanceFailed,
    /// Rekor transparency log upload failed
    RekorUploadFailed,
    /// Cryptographic signing error
    SigningError,
    /// Network/HTTP error
    NetworkError,
    /// Rate limited (client or server)
    RateLimited,
    /// Other/unknown error
    Other,
}

impl std::fmt::Display for SigningFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningFailure::TokenInvalid => write!(f, "token_invalid"),
            SigningFailure::CertificateIssuanceFailed => write!(f, "certificate_failed"),
            SigningFailure::RekorUploadFailed => write!(f, "rekor_failed"),
            SigningFailure::SigningError => write!(f, "signing_error"),
            SigningFailure::NetworkError => write!(f, "network_error"),
            SigningFailure::RateLimited => write!(f, "rate_limited"),
            SigningFailure::Other => write!(f, "other"),
        }
    }
}

/// Failure reasons for validation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationFailure {
    /// Signature doesn't match content
    InvalidSignature,
    /// Certificate has expired
    ExpiredCertificate,
    /// Certificate not from trusted CA
    UntrustedCertificate,
    /// No Rekor entry found
    MissingRekorEntry,
    /// Rekor inclusion proof invalid
    InvalidInclusionProof,
    /// Other/unknown error
    Other,
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationFailure::InvalidSignature => write!(f, "invalid_signature"),
            ValidationFailure::ExpiredCertificate => write!(f, "expired_certificate"),
            ValidationFailure::UntrustedCertificate => write!(f, "untrusted_certificate"),
            ValidationFailure::MissingRekorEntry => write!(f, "missing_rekor_entry"),
            ValidationFailure::InvalidInclusionProof => write!(f, "invalid_inclusion_proof"),
            ValidationFailure::Other => write!(f, "other"),
        }
    }
}

/// Labeled counter for tracking failures by reason
#[derive(Debug, Default)]
pub struct LabeledCounter<L: std::hash::Hash + Eq> {
    counts: RwLock<HashMap<L, u64>>,
}

impl<L: std::hash::Hash + Eq + Clone> LabeledCounter<L> {
    /// Create a new labeled counter
    pub fn new() -> Self {
        Self {
            counts: RwLock::new(HashMap::new()),
        }
    }

    /// Increment counter for a label
    pub fn increment(&self, label: L) {
        let mut counts = self.counts.write().unwrap();
        *counts.entry(label).or_insert(0) += 1;
    }

    /// Get current count for a label
    pub fn get(&self, label: &L) -> u64 {
        self.counts.read().unwrap().get(label).copied().unwrap_or(0)
    }

    /// Get all counts
    pub fn all(&self) -> HashMap<L, u64> {
        self.counts.read().unwrap().clone()
    }

    /// Get total across all labels
    pub fn total(&self) -> u64 {
        self.counts.read().unwrap().values().sum()
    }
}

/// Simple histogram for latency tracking
#[derive(Debug)]
pub struct Histogram {
    /// Bucket boundaries (upper limits in milliseconds)
    boundaries: Vec<u64>,
    /// Count per bucket (includes +Inf bucket)
    buckets: Vec<AtomicU64>,
    /// Sum of all values
    sum: AtomicU64,
    /// Total count
    count: AtomicU64,
}

impl Histogram {
    /// Create a histogram with the given bucket boundaries
    pub fn new(boundaries: Vec<u64>) -> Self {
        let buckets = (0..=boundaries.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            boundaries,
            buckets,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Create with default latency buckets (milliseconds)
    pub fn latency_default() -> Self {
        Self::new(vec![10, 50, 100, 250, 500, 1000, 2500, 5000, 10000])
    }

    /// Record a value
    pub fn record(&self, value_ms: u64) {
        self.sum.fetch_add(value_ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Find the bucket
        for (i, &boundary) in self.boundaries.iter().enumerate() {
            if value_ms <= boundary {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // +Inf bucket
        self.buckets[self.boundaries.len()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a duration
    pub fn record_duration(&self, duration: Duration) {
        self.record(duration.as_millis() as u64);
    }

    /// Get bucket counts with boundaries
    pub fn snapshot(&self) -> Vec<(u64, u64)> {
        let mut result = Vec::with_capacity(self.boundaries.len() + 1);

        for (i, &boundary) in self.boundaries.iter().enumerate() {
            result.push((boundary, self.buckets[i].load(Ordering::Relaxed)));
        }

        // +Inf bucket
        result.push((
            u64::MAX,
            self.buckets[self.boundaries.len()].load(Ordering::Relaxed),
        ));

        result
    }

    /// Get total count
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get sum of all values
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }
}

/// Metrics collection for wsc signing operations
#[derive(Debug)]
pub struct SigningMetrics {
    /// Total signing attempts
    pub signing_attempts: AtomicU64,
    /// Successful signings
    pub signing_success: AtomicU64,
    /// Signing failures by reason
    pub signing_failures: LabeledCounter<SigningFailure>,
    /// Signing latency histogram (ms)
    pub signing_duration: Histogram,

    /// Total validation attempts
    pub validation_attempts: AtomicU64,
    /// Successful validations
    pub validation_success: AtomicU64,
    /// Validation failures by reason
    pub validation_failures: LabeledCounter<ValidationFailure>,
    /// Validation latency histogram (ms)
    pub validation_duration: Histogram,

    /// Rate limit hits
    pub rate_limit_hits: AtomicU64,
    /// Server-side rate limits received
    pub server_rate_limits: AtomicU64,
}

impl Default for SigningMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            signing_attempts: AtomicU64::new(0),
            signing_success: AtomicU64::new(0),
            signing_failures: LabeledCounter::new(),
            signing_duration: Histogram::latency_default(),

            validation_attempts: AtomicU64::new(0),
            validation_success: AtomicU64::new(0),
            validation_failures: LabeledCounter::new(),
            validation_duration: Histogram::latency_default(),

            rate_limit_hits: AtomicU64::new(0),
            server_rate_limits: AtomicU64::new(0),
        }
    }

    /// Record a signing attempt start
    pub fn start_signing(&self) -> SigningTimer {
        self.signing_attempts.fetch_add(1, Ordering::Relaxed);
        SigningTimer {
            start: Instant::now(),
        }
    }

    /// Record a successful signing
    pub fn record_signing_success(&self, timer: SigningTimer) {
        self.signing_success.fetch_add(1, Ordering::Relaxed);
        self.signing_duration.record_duration(timer.elapsed());
    }

    /// Record a signing failure
    pub fn record_signing_failure(&self, reason: SigningFailure) {
        self.signing_failures.increment(reason);
    }

    /// Record a validation attempt start
    pub fn start_validation(&self) -> SigningTimer {
        self.validation_attempts.fetch_add(1, Ordering::Relaxed);
        SigningTimer {
            start: Instant::now(),
        }
    }

    /// Record a successful validation
    pub fn record_validation_success(&self, timer: SigningTimer) {
        self.validation_success.fetch_add(1, Ordering::Relaxed);
        self.validation_duration.record_duration(timer.elapsed());
    }

    /// Record a validation failure
    pub fn record_validation_failure(&self, reason: ValidationFailure) {
        self.validation_failures.increment(reason);
    }

    /// Record a rate limit hit (client-side)
    pub fn record_rate_limit_hit(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a server-side rate limit (429 response)
    pub fn record_server_rate_limit(&self) {
        self.server_rate_limits.fetch_add(1, Ordering::Relaxed);
    }

    /// Export metrics in Prometheus exposition format
    pub fn export_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        // Signing counters
        output.push_str(&format!(
            "# TYPE {prefix}signing_attempts_total counter\n\
             {prefix}signing_attempts_total {}\n\n",
            self.signing_attempts.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "# TYPE {prefix}signing_success_total counter\n\
             {prefix}signing_success_total {}\n\n",
            self.signing_success.load(Ordering::Relaxed)
        ));

        // Signing failures by reason
        output.push_str(&format!("# TYPE {prefix}signing_failures_total counter\n"));
        for (reason, count) in self.signing_failures.all() {
            output.push_str(&format!(
                "{prefix}signing_failures_total{{reason=\"{}\"}} {}\n",
                reason, count
            ));
        }
        output.push('\n');

        // Signing duration histogram
        output.push_str(&format!("# TYPE {prefix}signing_duration_ms histogram\n"));
        let mut cumulative = 0u64;
        for (boundary, count) in self.signing_duration.snapshot() {
            cumulative += count;
            let le = if boundary == u64::MAX {
                "+Inf".to_string()
            } else {
                boundary.to_string()
            };
            output.push_str(&format!(
                "{prefix}signing_duration_ms_bucket{{le=\"{}\"}} {}\n",
                le, cumulative
            ));
        }
        output.push_str(&format!(
            "{prefix}signing_duration_ms_sum {}\n",
            self.signing_duration.sum()
        ));
        output.push_str(&format!(
            "{prefix}signing_duration_ms_count {}\n\n",
            self.signing_duration.count()
        ));

        // Validation counters
        output.push_str(&format!(
            "# TYPE {prefix}validation_attempts_total counter\n\
             {prefix}validation_attempts_total {}\n\n",
            self.validation_attempts.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "# TYPE {prefix}validation_success_total counter\n\
             {prefix}validation_success_total {}\n\n",
            self.validation_success.load(Ordering::Relaxed)
        ));

        // Validation failures by reason
        output.push_str(&format!(
            "# TYPE {prefix}validation_failures_total counter\n"
        ));
        for (reason, count) in self.validation_failures.all() {
            output.push_str(&format!(
                "{prefix}validation_failures_total{{reason=\"{}\"}} {}\n",
                reason, count
            ));
        }
        output.push('\n');

        // Rate limiting
        output.push_str(&format!(
            "# TYPE {prefix}rate_limit_hits_total counter\n\
             {prefix}rate_limit_hits_total {}\n\n",
            self.rate_limit_hits.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "# TYPE {prefix}server_rate_limits_total counter\n\
             {prefix}server_rate_limits_total {}\n",
            self.server_rate_limits.load(Ordering::Relaxed)
        ));

        output
    }
}

/// Timer for measuring operation duration
pub struct SigningTimer {
    start: Instant,
}

impl SigningTimer {
    /// Get elapsed duration
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Global metrics instance
static GLOBAL_METRICS: std::sync::OnceLock<Arc<SigningMetrics>> = std::sync::OnceLock::new();

/// Get or create the global metrics instance
pub fn global_metrics() -> Arc<SigningMetrics> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(SigningMetrics::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_metrics() {
        let metrics = SigningMetrics::new();

        let timer = metrics.start_signing();
        std::thread::sleep(Duration::from_millis(10));
        metrics.record_signing_success(timer);

        assert_eq!(metrics.signing_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.signing_success.load(Ordering::Relaxed), 1);
        assert!(metrics.signing_duration.count() > 0);
    }

    #[test]
    fn test_signing_failures() {
        let metrics = SigningMetrics::new();

        metrics.record_signing_failure(SigningFailure::TokenInvalid);
        metrics.record_signing_failure(SigningFailure::TokenInvalid);
        metrics.record_signing_failure(SigningFailure::NetworkError);

        assert_eq!(metrics.signing_failures.get(&SigningFailure::TokenInvalid), 2);
        assert_eq!(metrics.signing_failures.get(&SigningFailure::NetworkError), 1);
        assert_eq!(metrics.signing_failures.total(), 3);
    }

    #[test]
    fn test_histogram() {
        let hist = Histogram::new(vec![10, 50, 100]);

        hist.record(5);   // bucket 0 (<=10)
        hist.record(25);  // bucket 1 (<=50)
        hist.record(75);  // bucket 2 (<=100)
        hist.record(200); // bucket 3 (+Inf)

        assert_eq!(hist.count(), 4);
        assert_eq!(hist.sum(), 305);

        let snapshot = hist.snapshot();
        assert_eq!(snapshot[0], (10, 1));  // <=10: 1
        assert_eq!(snapshot[1], (50, 1));  // <=50: 1
        assert_eq!(snapshot[2], (100, 1)); // <=100: 1
        assert_eq!(snapshot[3].1, 1);      // +Inf: 1
    }

    #[test]
    fn test_labeled_counter() {
        let counter: LabeledCounter<SigningFailure> = LabeledCounter::new();

        counter.increment(SigningFailure::TokenInvalid);
        counter.increment(SigningFailure::TokenInvalid);
        counter.increment(SigningFailure::RateLimited);

        assert_eq!(counter.get(&SigningFailure::TokenInvalid), 2);
        assert_eq!(counter.get(&SigningFailure::RateLimited), 1);
        assert_eq!(counter.get(&SigningFailure::Other), 0);
        assert_eq!(counter.total(), 3);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = SigningMetrics::new();

        metrics.signing_attempts.store(100, Ordering::Relaxed);
        metrics.signing_success.store(95, Ordering::Relaxed);
        metrics.record_signing_failure(SigningFailure::NetworkError);

        let output = metrics.export_prometheus("wsc_");

        assert!(output.contains("wsc_signing_attempts_total 100"));
        assert!(output.contains("wsc_signing_success_total 95"));
        assert!(output.contains("wsc_signing_failures_total{reason=\"network_error\"} 1"));
    }

    #[test]
    fn test_global_metrics() {
        let m1 = global_metrics();
        let m2 = global_metrics();

        m1.signing_attempts.fetch_add(1, Ordering::Relaxed);

        // Both should point to same instance
        assert_eq!(
            m2.signing_attempts.load(Ordering::Relaxed),
            m1.signing_attempts.load(Ordering::Relaxed)
        );
    }
}

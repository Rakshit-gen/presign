//! Prometheus counters and a latency histogram, kept in atomics.

use presign::Severity;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

const VERDICTS: [Severity; 5] = [
    Severity::Info,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];
/// Upper bounds in seconds. Offline analysis lands in the first buckets;
/// the upper ones are for requests that waited on chain lookups.
const BUCKETS: [f64; 10] = [
    0.000_05, 0.000_1, 0.000_25, 0.000_5, 0.001, 0.01, 0.1, 0.5, 1.0, 3.0,
];

#[derive(Default)]
pub struct Metrics {
    by_verdict: [AtomicU64; 5],
    rejected: AtomicU64,
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_nanos: AtomicU64,
}

impl Metrics {
    pub fn analyzed(&self, verdict: Severity, took: Duration) {
        let i = VERDICTS.iter().position(|v| *v == verdict).unwrap_or(0);
        self.by_verdict[i].fetch_add(1, Relaxed);
        let secs = took.as_secs_f64();
        for (b, bound) in self.buckets.iter().zip(BUCKETS) {
            if secs <= bound {
                b.fetch_add(1, Relaxed);
            }
        }
        self.count.fetch_add(1, Relaxed);
        self.sum_nanos.fetch_add(took.as_nanos() as u64, Relaxed);
    }

    pub fn rejected(&self) {
        self.rejected.fetch_add(1, Relaxed);
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        s += "# HELP presign_requests_total Requests analyzed, by verdict.\n";
        s += "# TYPE presign_requests_total counter\n";
        for (v, n) in VERDICTS.iter().zip(&self.by_verdict) {
            let _ = writeln!(
                s,
                "presign_requests_total{{verdict=\"{v}\"}} {}",
                n.load(Relaxed)
            );
        }
        s += "# HELP presign_rejected_total Requests rejected as malformed.\n";
        s += "# TYPE presign_rejected_total counter\n";
        let _ = writeln!(s, "presign_rejected_total {}", self.rejected.load(Relaxed));
        s += "# HELP presign_analyze_seconds Time to analyze one request.\n";
        s += "# TYPE presign_analyze_seconds histogram\n";
        for (b, bound) in self.buckets.iter().zip(BUCKETS) {
            let _ = writeln!(
                s,
                "presign_analyze_seconds_bucket{{le=\"{bound}\"}} {}",
                b.load(Relaxed)
            );
        }
        let count = self.count.load(Relaxed);
        let _ = writeln!(s, "presign_analyze_seconds_bucket{{le=\"+Inf\"}} {count}");
        let sum = self.sum_nanos.load(Relaxed) as f64 / 1e9;
        let _ = writeln!(s, "presign_analyze_seconds_sum {sum}");
        let _ = writeln!(s, "presign_analyze_seconds_count {count}");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_is_cumulative() {
        let m = Metrics::default();
        m.analyzed(Severity::Critical, Duration::from_micros(80));
        m.analyzed(Severity::Info, Duration::from_millis(2));
        let text = m.render();
        assert!(text.contains("presign_requests_total{verdict=\"critical\"} 1"));
        assert!(text.contains("le=\"0.00005\"} 0"));
        assert!(text.contains("le=\"0.0001\"} 1"));
        assert!(text.contains("le=\"0.01\"} 2"));
        assert!(text.contains("le=\"+Inf\"} 2"));
    }
}

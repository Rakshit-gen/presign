//! Scores presign on a dataset built by `presign-eval build`.

use presign::{Report, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

/// A request counts as flagged when its verdict reaches this severity.
pub const THRESHOLD: Severity = Severity::High;
const TIMING_PASSES: usize = 5;

pub struct Sample {
    pub label: String,
    pub kind: String,
    pub request: Value,
}

pub fn load(dir: &Path) -> Result<Vec<Sample>, String> {
    let raw = fs::read_to_string(dir.join("dataset.jsonl"))
        .map_err(|e| format!("{}: {e}; run `presign-eval build` first", dir.display()))?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).map_err(|e| e.to_string())?;
            Ok(Sample {
                label: v["label"].as_str().unwrap_or_default().to_string(),
                kind: v["kind"].as_str().unwrap_or_default().to_string(),
                request: v["request"].clone(),
            })
        })
        .collect()
}

/// 95% Wilson score interval for `k` successes out of `n`.
pub fn wilson(k: usize, n: usize) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    let (k, n, z) = (k as f64, n as f64, 1.96_f64);
    let p = k / n;
    let center = (p + z * z / (2.0 * n)) / (1.0 + z * z / n);
    let half = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt() / (1.0 + z * z / n);
    ((center - half).max(0.0), (center + half).min(1.0))
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i]
}

#[derive(Default)]
struct Tally {
    n: usize,
    flagged: usize,
}

pub fn score(samples: &[Sample], mut judge: impl FnMut(&Value) -> Result<Report, String>) -> Value {
    let mut by_kind: BTreeMap<(String, String), Tally> = BTreeMap::new();
    let mut misses: BTreeMap<String, usize> = BTreeMap::new();
    let mut false_alarms: BTreeMap<String, usize> = BTreeMap::new();
    let mut errors = 0;
    let mut latencies_us = Vec::with_capacity(samples.len() * TIMING_PASSES);

    for s in samples {
        let report = match judge(&s.request) {
            Ok(r) => r,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        for _ in 0..TIMING_PASSES {
            let t = Instant::now();
            let _ = judge(&s.request);
            latencies_us.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let flagged = report.verdict() >= THRESHOLD;
        let tally = by_kind
            .entry((s.label.clone(), s.kind.clone()))
            .or_default();
        tally.n += 1;
        tally.flagged += usize::from(flagged);
        let code = report.top().map_or("none", |f| f.code).to_string();
        match (s.label.as_str(), flagged) {
            ("drainer", false) => *misses.entry(code).or_default() += 1,
            ("benign", true) => *false_alarms.entry(code).or_default() += 1,
            _ => {}
        }
    }
    latencies_us.sort_by(f64::total_cmp);

    let total = |label: &str| {
        by_kind
            .iter()
            .filter(|((l, _), _)| l == label)
            .fold((0, 0), |(n, f), (_, t)| (n + t.n, f + t.flagged))
    };
    let (drainers, caught) = total("drainer");
    let (benign, flagged_benign) = total("benign");
    let rate = |k, n| {
        json!({"k": k, "n": n, "rate": if n == 0 { 0.0 } else { k as f64 / n as f64 },
                             "ci95": wilson(k, n)})
    };
    json!({
        "threshold": THRESHOLD.to_string(),
        "recall": rate(caught, drainers),
        "false_positive_rate": rate(flagged_benign, benign),
        "errors": errors,
        "latency_us": {
            "p50": percentile(&latencies_us, 0.50),
            "p99": percentile(&latencies_us, 0.99),
            "max": latencies_us.last().copied().unwrap_or_default(),
            "calls": latencies_us.len(),
        },
        "by_kind": by_kind.iter().map(|((l, k), t)| json!({
            "label": l, "kind": k, "n": t.n, "flagged": t.flagged,
        })).collect::<Vec<_>>(),
        "missed_drainers_by_top_code": misses,
        "false_alarms_by_top_code": false_alarms,
    })
}

pub fn markdown(r: &Value) -> String {
    let pct = |v: &Value| format!("{:.1}%", v.as_f64().unwrap_or_default() * 100.0);
    let ci = |v: &Value| format!("{} to {}", pct(&v[0]), pct(&v[1]));
    let mut s = String::new();
    s += &format!(
        "| Metric | Value | 95% CI |\n|---|---|---|\n\
         | Recall (drainer requests flagged {th}+) | {} ({}/{}) | {} |\n\
         | False positive rate (benign flagged {th}+) | {} ({}/{}) | {} |\n\
         | Latency p50 / p99 per request | {:.1} / {:.1} µs | |\n\n",
        pct(&r["recall"]["rate"]),
        r["recall"]["k"],
        r["recall"]["n"],
        ci(&r["recall"]["ci95"]),
        pct(&r["false_positive_rate"]["rate"]),
        r["false_positive_rate"]["k"],
        r["false_positive_rate"]["n"],
        ci(&r["false_positive_rate"]["ci95"]),
        r["latency_us"]["p50"].as_f64().unwrap_or_default(),
        r["latency_us"]["p99"].as_f64().unwrap_or_default(),
        th = r["threshold"].as_str().unwrap_or_default(),
    );
    s += "| Label | Kind | Samples | Flagged |\n|---|---|---|---|\n";
    for row in r["by_kind"].as_array().into_iter().flatten() {
        s += &format!(
            "| {} | {} | {} | {} |\n",
            row["label"].as_str().unwrap_or_default(),
            row["kind"].as_str().unwrap_or_default(),
            row["n"],
            row["flagged"]
        );
    }
    for (title, key) in [
        (
            "Missed drainer requests by top finding",
            "missed_drainers_by_top_code",
        ),
        ("False alarms by top finding", "false_alarms_by_top_code"),
    ] {
        s += &format!("\n{title}:\n\n");
        for (code, n) in r[key].as_object().into_iter().flatten() {
            s += &format!("- `{code}`: {n}\n");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wilson_interval_matches_known_values() {
        let (lo, hi) = wilson(8, 10);
        assert!((lo - 0.4902).abs() < 1e-3 && (hi - 0.9433).abs() < 1e-3);
        assert_eq!(wilson(0, 0), (0.0, 0.0));
    }

    #[test]
    fn score_counts_recall_and_false_positives() {
        let sample = |label: &str, method: &str| Sample {
            label: label.into(),
            kind: "k".into(),
            request: json!({"method": method, "params": ["0x00", "0x00"]}),
        };
        let samples = [
            sample("drainer", "eth_sign"),
            sample("drainer", "personal_sign"),
            sample("benign", "personal_sign"),
        ];
        let r = score(&samples, presign::analyze);
        assert_eq!(r["recall"]["k"], 1);
        assert_eq!(r["recall"]["n"], 2);
        assert_eq!(r["false_positive_rate"]["k"], 0);
        assert_eq!(r["missed_drainers_by_top_code"]["sign.binary"], 1);
    }
}

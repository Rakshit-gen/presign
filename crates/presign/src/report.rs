//! Findings, severities and the report returned by [`crate::analyze`].

use alloy_primitives::B256;
use serde_json::{Value, json};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Set for typed-data requests: the hashes a hardware wallet displays.
    pub hashes: Option<Hashes>,
}

/// EIP-712 hashes computed from the exact typed data in the request.
/// `signing` is what gets signed (and what Safe calls the safeTxHash);
/// `domain` and `message` are what Ledger shows when blind signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashes {
    pub signing: B256,
    pub domain: B256,
    pub message: B256,
}

impl Report {
    /// The highest severity among all findings.
    pub fn verdict(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "verdict": self.verdict().to_string(),
            "hashes": self.hashes.map(|h| json!({
                "signing": h.signing, "domain": h.domain, "message": h.message,
            })),
            "findings": self.findings.iter()
                .map(|f| json!({"severity": f.severity.to_string(), "message": f.message}))
                .collect::<Vec<_>>(),
        })
    }

    pub(crate) fn add(&mut self, severity: Severity, message: impl Into<String>) {
        self.findings.push(Finding {
            severity,
            message: message.into(),
        });
    }
}

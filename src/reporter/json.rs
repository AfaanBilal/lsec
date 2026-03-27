//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use serde::Serialize;

use crate::models::{Finding, ScanContext, Severity};

#[derive(Serialize)]
struct JsonReport<'a> {
    root: String,
    summary_only: bool,
    counts: Counts,
    findings: &'a [Finding],
}

#[derive(Serialize)]
struct Counts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

pub fn render(
    findings: &[Finding],
    context: &ScanContext,
    summary_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let counts = Counts {
        critical: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        info: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count(),
        total: findings.len(),
    };
    let report = JsonReport {
        root: context.root.to_string_lossy().to_string(),
        summary_only,
        counts,
        findings: if summary_only { &[] } else { findings },
    };
    Ok(serde_json::to_string_pretty(&report)?)
}

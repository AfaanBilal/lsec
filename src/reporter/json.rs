//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use serde::Serialize;

use crate::models::{Category, Finding, ScanContext, Severity};

#[derive(Serialize)]
struct JsonReport<'a> {
    root: String,
    summary_only: bool,
    counts: Counts,
    categories: Vec<CategoryCount>,
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

#[derive(Serialize)]
struct CategoryCount {
    category: &'static str,
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
        categories: categories(findings),
        findings: if summary_only { &[] } else { findings },
    };
    Ok(serde_json::to_string_pretty(&report)?)
}

fn categories(findings: &[Finding]) -> Vec<CategoryCount> {
    let ordered = [
        Category::Env,
        Category::Auth,
        Category::Injection,
        Category::Http,
        Category::Storage,
        Category::Deps,
        Category::Secrets,
        Category::Logging,
    ];
    ordered
        .iter()
        .map(|category| CategoryCount {
            category: category.as_str(),
            total: findings
                .iter()
                .filter(|finding| finding.category == *category)
                .count(),
        })
        .filter(|entry| entry.total > 0)
        .collect()
}

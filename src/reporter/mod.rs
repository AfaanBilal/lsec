//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
pub mod json;
pub mod sarif;
pub mod terminal;

use crate::models::{Finding, ScanContext};

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Pretty,
    Json,
    Sarif,
}

pub fn render_report(
    format: ReportFormat,
    findings: &[Finding],
    context: &ScanContext,
    summary_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match format {
        ReportFormat::Pretty => terminal::render(findings, summary_only),
        ReportFormat::Json => json::render(findings, context, summary_only)?,
        ReportFormat::Sarif => sarif::render(findings, context, summary_only)?,
    })
}

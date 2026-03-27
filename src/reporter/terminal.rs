//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use colored::Colorize;

use crate::models::{Finding, Severity};

pub fn render(findings: &[Finding], summary_only: bool) -> String {
    let mut output = String::new();
    let counts = counts(findings);
    if summary_only {
        output.push_str(&format_summary(&counts));
        return output;
    }

    for finding in findings {
        let severity = paint(finding.severity, finding.severity.as_str());
        output.push_str(&format!(
            "[{severity}] {}: {}\n",
            finding.category.as_str(),
            finding.title
        ));
        output.push_str(&format!("  Rule: {}\n", finding.rule_id));
        output.push_str(&format!("  {}\n", finding.message));
        if let Some(file) = &finding.file {
            output.push_str(&format!("  File: {}", file));
            if let Some(line) = finding.line {
                output.push_str(&format!(":{line}"));
            }
            output.push('\n');
        }
        if let Some(snippet) = &finding.snippet {
            output.push_str(&format!("  Code: {snippet}\n"));
        }
        output.push('\n');
    }

    output.push_str(&format_summary(&counts));
    output
}

fn paint(severity: Severity, label: &str) -> colored::ColoredString {
    match severity {
        Severity::Critical => label.red().bold(),
        Severity::High => label.red(),
        Severity::Medium => label.yellow(),
        Severity::Low => label.cyan(),
        Severity::Info => label.normal(),
    }
}

fn counts(findings: &[Finding]) -> [usize; 5] {
    let mut counts = [0; 5];
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts[0] += 1,
            Severity::High => counts[1] += 1,
            Severity::Medium => counts[2] += 1,
            Severity::Low => counts[3] += 1,
            Severity::Info => counts[4] += 1,
        }
    }
    counts
}

fn format_summary(counts: &[usize; 5]) -> String {
    format!(
        "Summary: critical={}, high={}, medium={}, low={}, info={}, total={}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
        counts.iter().sum::<usize>()
    )
}

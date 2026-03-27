//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use colored::Colorize;

use crate::models::{Category, Finding, Severity};

pub fn render(findings: &[Finding], summary_only: bool) -> String {
    let mut output = String::new();
    let counts = counts(findings);
    if summary_only {
        output.push_str(&format_summary(&counts));
        output.push('\n');
        output.push_str(&format_category_summary(findings));
        return output;
    }

    output.push_str(&format_summary(&counts));
    output.push('\n');
    output.push_str(&format_category_summary(findings));
    output.push_str("\n\n");

    for category in categories() {
        let category_findings: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.category == category)
            .collect();
        if category_findings.is_empty() {
            continue;
        }

        output.push_str(&format!(
            "{} {}\n",
            category_code(category).bold(),
            category_label(category).bold()
        ));
        for finding in category_findings {
            let severity = paint(finding.severity, finding.severity.as_str());
            output.push_str(&format!("  [{severity}] {}\n", finding.title));
            output.push_str(&format!("    Rule: {}\n", finding.rule_id));
            output.push_str(&format!("    Confidence: {:.0}%\n", finding.confidence * 100.0));
            output.push_str(&format!("    {}\n", finding.message));
            output.push_str(&format!("    Fix: {}\n", finding.remediation));
            if let Some(file) = &finding.file {
                output.push_str(&format!("    File: {}", file));
                if let Some(line) = finding.line {
                    output.push_str(&format!(":{line}"));
                }
                output.push('\n');
            }
            if let Some(snippet) = &finding.snippet {
                output.push_str(&format!("    Code: {snippet}\n"));
            }
            output.push('\n');
        }
    }

    output.trim_end().to_string()
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

fn format_category_summary(findings: &[Finding]) -> String {
    let mut lines = Vec::new();
    for category in categories() {
        let count = findings.iter().filter(|finding| finding.category == category).count();
        if count > 0 {
            lines.push(format!("  {} {}={}", category_code(category), category.as_str(), count));
        }
    }
    if lines.is_empty() {
        "By category: none".to_string()
    } else {
        format!("By category:\n{}", lines.join("\n"))
    }
}

fn categories() -> [Category; 8] {
    [
        Category::Env,
        Category::Auth,
        Category::Injection,
        Category::Http,
        Category::Storage,
        Category::Deps,
        Category::Secrets,
        Category::Logging,
    ]
}

fn category_code(category: Category) -> &'static str {
    match category {
        Category::Env => "ENV",
        Category::Auth => "AUTH",
        Category::Injection => "INJ",
        Category::Http => "HTTP",
        Category::Storage => "FS",
        Category::Deps => "DEPS",
        Category::Secrets => "SEC",
        Category::Logging => "LOG",
    }
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Env => "Environment",
        Category::Auth => "Authentication",
        Category::Injection => "Injection",
        Category::Http => "HTTP",
        Category::Storage => "Storage",
        Category::Deps => "Dependencies",
        Category::Secrets => "Secrets",
        Category::Logging => "Logging",
    }
}

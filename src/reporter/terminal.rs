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

    output.push_str(&format_banner());
    output.push('\n');
    output.push_str(&format_overview(&counts, findings, "Scan Summary"));

    if summary_only {
        return output;
    }

    for category in categories() {
        let category_findings: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.category == category)
            .collect();
        if category_findings.is_empty() {
            continue;
        }

        output.push_str("\n\n");
        output.push_str(&format!(
            "{} {} ({})\n",
            category_code(category).bold(),
            category_label(category).bold(),
            category_findings.len()
        ));
        output.push_str(&format!("{}\n", "=".repeat(72).dimmed()));

        for (index, finding) in category_findings.iter().enumerate() {
            let severity = paint(finding.severity, finding.severity.as_str());
            output.push_str(&format!("[{}] {}\n", severity, finding.title.bold()));
            output.push_str(&format!("  {} {}\n", label("Rule"), finding.rule_id.dimmed()));
            output.push_str(&format!(
                "  {} {:.0}%\n",
                label("Confidence"),
                finding.confidence * 100.0
            ));
            output.push_str(&format!("  {} {}\n", label("Why"), finding.message));
            output.push_str(&format!("  {} {}\n", label("Fix"), finding.remediation));
            if let Some(file) = &finding.file {
                output.push_str(&format!("  {} {}", label("Location"), file.cyan()));
                if let Some(line) = finding.line {
                    output.push_str(&format!(":{}", line.to_string().cyan()));
                }
                output.push('\n');
            }
            if let Some(snippet) = &finding.snippet {
                output.push_str(&format!("  {} {}\n", label("Snippet"), snippet.trim()));
            }
            if index + 1 != category_findings.len() {
                output.push_str(&format!("  {}\n", "-".repeat(68).dimmed()));
            }
            output.push('\n');
        }
    }

    output.push_str("\n");
    output.push_str(&format_overview(&counts, findings, "Closing Summary"));

    output.trim_end().to_string()
}

fn format_banner() -> String {
    format!(
        "{} {}",
        "Laravel Security Audit CLI".bold(),
        "
© Afaan Bilal <https://afaan.dev>
"
    )
}

fn label(text: &str) -> colored::ColoredString {
    format!("{text:<10}").bold()
}

fn paint(severity: Severity, label: &str) -> colored::ColoredString {
    match severity {
        Severity::Critical => label.red().bold(),
        Severity::High => label.red().bold(),
        Severity::Medium => label.yellow().bold(),
        Severity::Low => label.cyan().bold(),
        Severity::Info => label.bold(),
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

fn format_overview(counts: &[usize; 5], findings: &[Finding], title: &str) -> String {
    let total = counts.iter().sum::<usize>();
    let mut output = String::new();

    output.push_str(&format!("{}\n", title.bold()));
    output.push_str(&format!("{}\n", "+------------+----------+".dimmed()));
    output.push_str(&format!("| {:<10} | {:>8} |\n", "Severity".bold(), "Count".bold()));
    output.push_str(&format!("{}\n", "+------------+----------+".dimmed()));
    output.push_str(&format!("| {:<10} | {:>8} |\n", paint(Severity::Critical, "critical"), counts[0]));
    output.push_str(&format!("| {:<10} | {:>8} |\n", paint(Severity::High, "high"), counts[1]));
    output.push_str(&format!("| {:<10} | {:>8} |\n", paint(Severity::Medium, "medium"), counts[2]));
    output.push_str(&format!("| {:<10} | {:>8} |\n", paint(Severity::Low, "low"), counts[3]));
    output.push_str(&format!("| {:<10} | {:>8} |\n", paint(Severity::Info, "info"), counts[4]));
    output.push_str(&format!("{}\n", "+------------+----------+".dimmed()));
    output.push_str(&format!("| {:<10} | {:>8} |\n", "total".bold(), total));
    output.push_str(&format!("{}\n\n", "+------------+----------+".dimmed()));
    output.push_str(&format_category_table(findings));

    output
}

fn format_category_table(findings: &[Finding]) -> String {
    let mut rows = Vec::new();
    for category in categories() {
        let count = findings.iter().filter(|finding| finding.category == category).count();
        if count > 0 {
            rows.push((category_code(category), category_label(category), count));
        }
    }

    let mut output = String::new();
    output.push_str(&format!("{}\n", "Category Breakdown".bold()));
    output.push_str(&format!("{}\n", "+------+----------------+----------+".dimmed()));
    output.push_str(&format!("| {:<4} | {:<14} | {:>8} |\n", "Code".bold(), "Category".bold(), "Count".bold()));
    output.push_str(&format!("{}\n", "+------+----------------+----------+".dimmed()));

    if rows.is_empty() {
        output.push_str(&format!("| {:<4} | {:<14} | {:>8} |\n", "-", "none", 0));
    } else {
        for (code, label, count) in rows {
            output.push_str(&format!("| {:<4} | {:<14} | {:>8} |\n", code.bold(), label, count));
        }
    }

    output.push_str(&format!("{}", "+------+----------------+----------+".dimmed()));
    output
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

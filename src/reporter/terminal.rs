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
    output.push_str(&format_summary(&counts));
    output.push('\n');
    output.push_str(&format_category_summary(findings));

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
        output.push_str(&format!("{}\n", "─".repeat(72).dimmed()));

        for finding in category_findings {
            let severity = paint(finding.severity, finding.severity.as_str());
            output.push_str(&format!("[{severity}] {}\n", finding.title.bold()));
            output.push_str(&format!("  Rule       {}\n", finding.rule_id.dimmed()));
            output.push_str(&format!(
                "  Confidence {:.0}%\n",
                finding.confidence * 100.0
            ));
            output.push_str(&format!("  Why        {}\n", finding.message));
            output.push_str(&format!("  Fix        {}\n", finding.remediation));
            if let Some(file) = &finding.file {
                output.push_str(&format!("  Location   {}", file.cyan()));
                if let Some(line) = finding.line {
                    output.push_str(&format!(":{}", line.to_string().cyan()));
                }
                output.push('\n');
            }
            if let Some(snippet) = &finding.snippet {
                output.push_str(&format!("  Snippet    {}\n", snippet.trim()));
            }
            output.push('\n');
        }
    }

    output.trim_end().to_string()
}

fn format_banner() -> String {
    format!(
        "{}\n{}",
        "lsec".bold(),
        "Laravel Security Audit CLI".dimmed()
    )
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
    let total = counts.iter().sum::<usize>();
    format!(
        "Summary  {}  {}  {}  {}  {}  total={} ",
        paint(Severity::Critical, &format!("critical={}", counts[0])),
        paint(Severity::High, &format!("high={}", counts[1])),
        paint(Severity::Medium, &format!("medium={}", counts[2])),
        paint(Severity::Low, &format!("low={}", counts[3])),
        paint(Severity::Info, &format!("info={}", counts[4])),
        total
    )
}

fn format_category_summary(findings: &[Finding]) -> String {
    let mut entries = Vec::new();
    for category in categories() {
        let count = findings
            .iter()
            .filter(|finding| finding.category == category)
            .count();
        if count > 0 {
            entries.push(format!("{} {}", category_code(category), count));
        }
    }
    if entries.is_empty() {
        "Categories  none".to_string()
    } else {
        format!("Categories  {}", entries.join("  "))
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

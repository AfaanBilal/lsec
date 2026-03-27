//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use colored::Colorize;

use crate::models::{Category, Finding, Severity};

const WRAP_WIDTH: usize = 96;
const DETAIL_INDENT: &str = "  ";
const BLOCK_INDENT: &str = "    ";

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
        output.push_str(&format!("{}\n", "=".repeat(84).dimmed()));

        for (index, finding) in category_findings.iter().enumerate() {
            output.push_str(&format_finding_block(finding));
            if index + 1 != category_findings.len() {
                output.push_str(&format!("{}\n\n", "-".repeat(84).dimmed()));
            }
        }
    }

    output.push_str("\n\n");
    output.push_str(&format_overview(&counts, findings, "Closing Summary"));

    output.trim_end().to_string()
}

fn format_finding_block(finding: &Finding) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{} {}\n",
        severity_badge(finding.severity),
        finding.title.bold()
    ));
    output.push_str(&format!("{}{}\n", DETAIL_INDENT, meta_line(finding)));
    output.push_str(&format!(
        "{}{}\n",
        DETAIL_INDENT,
        key_value_line("Location", &display_location(finding))
    ));
    output.push_str(&wrapped_field("Why", &finding.message));
    output.push_str(&wrapped_field("Fix", finding.remediation));
    if let Some(snippet) = &finding.snippet {
        output.push_str(&snippet_block(snippet.trim()));
    }
    output
}

fn meta_line(finding: &Finding) -> String {
    format!(
        "{}  {}  {}",
        key_value_inline("Rule", &finding.rule_id.dimmed().to_string()),
        key_value_inline("Confidence", &format!("{:.0}%", finding.confidence * 100.0)),
        key_value_inline("Severity", finding.severity.as_str())
    )
}

fn key_value_inline(label_text: &str, value: &str) -> String {
    format!("{} {}", label(label_text), value)
}

fn key_value_line(label_text: &str, value: &str) -> String {
    format!("{} {}", label(label_text), value)
}

fn wrapped_field(label_text: &str, value: &str) -> String {
    let mut output = String::new();
    output.push_str(&format!("{}{}\n", DETAIL_INDENT, label(label_text)));
    for line in wrap_text(value, WRAP_WIDTH.saturating_sub(BLOCK_INDENT.len())) {
        output.push_str(&format!("{}{}\n", BLOCK_INDENT, line));
    }
    output
}

fn snippet_block(snippet: &str) -> String {
    let mut output = String::new();
    output.push_str(&format!("{}{}\n", DETAIL_INDENT, label("Snippet")));
    for line in wrap_text(snippet, WRAP_WIDTH.saturating_sub(BLOCK_INDENT.len() + 2)) {
        output.push_str(&format!("{}{} {}\n", BLOCK_INDENT, ">".dimmed(), line));
    }
    output
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();

    for paragraph in text.lines() {
        let trimmed = paragraph.trim();
        if trimmed.is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for word in trimmed.split_whitespace() {
            let next_len = if current.is_empty() {
                word.len()
            } else {
                current.len() + 1 + word.len()
            };

            if next_len > width && !current.is_empty() {
                lines.push(current);
                current = word.to_string();
            } else {
                if !current.is_empty() {
                    current.push(' ');
                }
                current.push_str(word);
            }
        }

        if !current.is_empty() {
            lines.push(current);
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn display_location(finding: &Finding) -> String {
    match (&finding.file, finding.line) {
        (Some(file), Some(line)) => format!("{}:{}", file.cyan(), line.to_string().cyan()),
        (Some(file), None) => file.cyan().to_string(),
        _ => "n/a".dimmed().to_string(),
    }
}

fn format_banner() -> String {
    format!(
        "{}\n{}\n",
        "Laravel Security Audit CLI".bold(),
        "© Afaan Bilal <https://afaan.dev>"
    )
}

fn label(text: &str) -> colored::ColoredString {
    format!("{text}:").bold()
}

fn severity_badge(severity: Severity) -> colored::ColoredString {
    let badge = format!("[{}]", severity.as_str());
    match severity {
        Severity::Critical => badge.red().bold(),
        Severity::High => badge.red().bold(),
        Severity::Medium => badge.yellow().bold(),
        Severity::Low => badge.cyan().bold(),
        Severity::Info => badge.bold(),
    }
}

fn paint(severity: Severity, text: &str) -> colored::ColoredString {
    match severity {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red().bold(),
        Severity::Medium => text.yellow().bold(),
        Severity::Low => text.cyan().bold(),
        Severity::Info => text.bold(),
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
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        "Severity".bold(),
        "Count".bold()
    ));
    output.push_str(&format!("{}\n", "+------------+----------+".dimmed()));
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        paint(Severity::Critical, "critical"),
        counts[0]
    ));
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        paint(Severity::High, "high"),
        counts[1]
    ));
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        paint(Severity::Medium, "medium"),
        counts[2]
    ));
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        paint(Severity::Low, "low"),
        counts[3]
    ));
    output.push_str(&format!(
        "| {:<10} | {:>8} |\n",
        paint(Severity::Info, "info"),
        counts[4]
    ));
    output.push_str(&format!("{}\n", "+------------+----------+".dimmed()));
    output.push_str(&format!("| {:<10} | {:>8} |\n", "total".bold(), total));
    output.push_str(&format!("{}\n\n", "+------------+----------+".dimmed()));
    output.push_str(&format_category_table(findings));

    output
}

fn format_category_table(findings: &[Finding]) -> String {
    let mut rows = Vec::new();
    for category in categories() {
        let count = findings
            .iter()
            .filter(|finding| finding.category == category)
            .count();
        if count > 0 {
            rows.push((category_code(category), category_label(category), count));
        }
    }

    let mut output = String::new();
    output.push_str(&format!("{}\n", "Category Breakdown".bold()));
    output.push_str(&format!(
        "{}\n",
        "+------+----------------+----------+".dimmed()
    ));
    output.push_str(&format!(
        "| {:<4} | {:<14} | {:>8} |\n",
        "Code".bold(),
        "Category".bold(),
        "Count".bold()
    ));
    output.push_str(&format!(
        "{}\n",
        "+------+----------------+----------+".dimmed()
    ));

    if rows.is_empty() {
        output.push_str(&format!("| {:<4} | {:<14} | {:>8} |\n", "-", "none", 0));
    } else {
        for (code, label, count) in rows {
            output.push_str(&format!(
                "| {:<4} | {:<14} | {:>8} |\n",
                code.bold(),
                label,
                count
            ));
        }
    }

    output.push_str(&format!(
        "{}",
        "+------+----------------+----------+".dimmed()
    ));
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

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::render;
    use crate::models::{Category, Finding, Severity};

    fn strip_ansi(input: &str) -> String {
        Regex::new(r"\x1b\[[0-9;]*m")
            .unwrap()
            .replace_all(input, "")
            .to_string()
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "http.ssrf-user-url",
            title: "User-controlled outbound URL".to_string(),
            message: "User input flows into an outbound HTTP client call.".to_string(),
            remediation: "Allowlist outbound destinations and block internal address space."
                .to_string()
                .leak(),
            confidence: 0.79,
            severity: Severity::High,
            category: Category::Http,
            file: Some("app/Services/Webhook.php".to_string()),
            line: Some(12),
            snippet: Some("Http::get($request->input('url'));".to_string()),
        }
    }

    #[test]
    fn summary_snapshot_stays_stable() {
        let rendered = strip_ansi(&render(&[], true));
        let expected = "Laravel Security Audit CLI\n© Afaan Bilal <https://afaan.dev>\n\nScan Summary\n+------------+----------+\n| Severity   |    Count |\n+------------+----------+\n| critical   |        0 |\n| high       |        0 |\n| medium     |        0 |\n| low        |        0 |\n| info       |        0 |\n+------------+----------+\n| total      |        0 |\n+------------+----------+\n\nCategory Breakdown\n+------+----------------+----------+\n| Code | Category       |    Count |\n+------+----------------+----------+\n| -    | none           |        0 |\n+------+----------------+----------+";
        assert_eq!(rendered.trim(), expected);
    }

    #[test]
    fn finding_snapshot_stays_structured() {
        let rendered = strip_ansi(&render(&[sample_finding()], false));
        assert!(rendered.contains("[HIGH] User-controlled outbound URL"));
        assert!(rendered.contains("Rule: http.ssrf-user-url"));
        assert!(rendered.contains("Confidence: 79%"));
        assert!(rendered.contains("Severity: HIGH"));
        assert!(rendered.contains("Location: app/Services/Webhook.php:12"));
        assert!(rendered.contains("Why:"));
        assert!(rendered.contains("User input flows into an outbound HTTP client call."));
        assert!(rendered.contains("Fix:"));
        assert!(
            rendered.contains("Allowlist outbound destinations and block internal address space.")
        );
        assert!(rendered.contains("Snippet:"));
        assert!(rendered.contains("> Http::get($request->input('url'));"));
        assert!(rendered.contains("Closing Summary"));
    }
}

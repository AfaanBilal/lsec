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
const SNIPPET_BG: (u8, u8, u8) = (28, 32, 40);
const SECTION_WIDTH: usize = 104;

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
        output.push_str(&format!("{}\n", "=".repeat(SECTION_WIDTH).dimmed()));

        for (index, finding) in category_findings.iter().enumerate() {
            output.push_str(&format_finding_block(finding));
            if index + 1 != category_findings.len() {
                output.push_str(&format!("{}\n\n", "-".repeat(SECTION_WIDTH).dimmed()));
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
        output.push_str(&snippet_block(finding, snippet.trim()));
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

fn snippet_block(finding: &Finding, snippet: &str) -> String {
    let mut output = String::new();
    output.push_str(&format!("{}{}\n", DETAIL_INDENT, label("Snippet")));
    for raw_line in snippet.lines() {
        let line = raw_line.trim();
        let highlighted = if line.is_empty() {
            String::new()
        } else {
            highlight_snippet_line(line, finding.file.as_deref())
        };
        output.push_str(&format!(
            "{}{}\n",
            BLOCK_INDENT,
            snippet_panel_line(&highlighted)
        ));
    }
    output
}

fn snippet_panel_line(content: &str) -> colored::ColoredString {
    format!("  {content:<90}  ").on_truecolor(SNIPPET_BG.0, SNIPPET_BG.1, SNIPPET_BG.2)
}

fn highlight_snippet_line(line: &str, file: Option<&str>) -> String {
    match snippet_language(file) {
        SnippetLanguage::Php => highlight_php_line(line),
        SnippetLanguage::Plain => line.to_string(),
    }
}

#[derive(Copy, Clone)]
enum SnippetLanguage {
    Php,
    Plain,
}

fn snippet_language(file: Option<&str>) -> SnippetLanguage {
    match file.and_then(file_extension) {
        Some("php") => SnippetLanguage::Php,
        _ => SnippetLanguage::Plain,
    }
}

fn file_extension(path: &str) -> Option<&str> {
    path.rsplit_once('.').map(|(_, ext)| ext)
}

fn highlight_php_line(line: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if ch == '\'' || ch == '"' {
            let quote = ch;
            let mut token = String::new();
            token.push(ch);
            i += 1;
            while i < chars.len() {
                let current = chars[i];
                token.push(current);
                i += 1;
                if current == quote && !is_escaped(&token) {
                    break;
                }
            }
            out.push_str(&token.green().to_string());
            continue;
        }

        if ch == '$' {
            let mut token = String::from("$");
            i += 1;
            while i < chars.len() && is_ident_char(chars[i]) {
                token.push(chars[i]);
                i += 1;
            }
            out.push_str(&token.cyan().to_string());
            continue;
        }

        if is_ident_start(ch) {
            let mut token = String::new();
            token.push(ch);
            i += 1;
            while i < chars.len() && is_ident_char(chars[i]) {
                token.push(chars[i]);
                i += 1;
            }
            out.push_str(&style_php_identifier(&token));
            continue;
        }

        out.push(ch);
        i += 1;
    }

    out
}

fn is_escaped(token: &str) -> bool {
    let mut backslashes = 0;
    for ch in token.chars().rev().skip(1) {
        if ch == '\\' {
            backslashes += 1;
        } else {
            break;
        }
    }
    backslashes % 2 == 1
}

fn style_php_identifier(token: &str) -> String {
    match token {
        "if" | "else" | "elseif" | "match" | "fn" | "function" | "return" | "new" | "throw"
        | "try" | "catch" | "use" | "public" | "protected" | "private" | "static" | "class"
        | "extends" | "implements" | "null" | "true" | "false" => token.yellow().bold().to_string(),
        "Route" | "Http" | "Storage" | "DB" | "Gate" | "Policy" | "Hash" | "Auth" | "Request"
        | "Response" => token.blue().bold().to_string(),
        _ => token.to_string(),
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
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
    let severity_table = severity_table_lines(counts);
    let category_table = category_table_lines(findings);
    let category_title = "Category Breakdown".bold().to_string();
    let left_width = severity_table
        .iter()
        .map(|line| visible_width(line))
        .max()
        .unwrap_or(0);

    let mut output = String::new();
    output.push_str(&format!("{}", title.bold()));
    output.push_str(&" ".repeat(left_width.saturating_sub(visible_width(title)) + 4));
    output.push_str(&category_title);
    output.push('\n');

    for idx in 0..severity_table.len().max(category_table.len()) {
        let left = severity_table.get(idx).map(String::as_str).unwrap_or("");
        let right = category_table.get(idx).map(String::as_str).unwrap_or("");
        output.push_str(left);
        if !right.is_empty() {
            let pad = left_width.saturating_sub(visible_width(left)) + 4;
            output.push_str(&" ".repeat(pad));
            output.push_str(right);
        }
        output.push('\n');
    }

    output.trim_end().to_string()
}

fn severity_table_lines(counts: &[usize; 5]) -> Vec<String> {
    let total = counts.iter().sum::<usize>();
    vec![
        "+------------+----------+".dimmed().to_string(),
        format!("| {:<10} | {:>8} |", "Severity".bold(), "Count".bold()),
        "+------------+----------+".dimmed().to_string(),
        format!(
            "| {:<10} | {:>8} |",
            paint(Severity::Critical, "critical"),
            counts[0]
        ),
        format!(
            "| {:<10} | {:>8} |",
            paint(Severity::High, "high"),
            counts[1]
        ),
        format!(
            "| {:<10} | {:>8} |",
            paint(Severity::Medium, "medium"),
            counts[2]
        ),
        format!("| {:<10} | {:>8} |", paint(Severity::Low, "low"), counts[3]),
        format!(
            "| {:<10} | {:>8} |",
            paint(Severity::Info, "info"),
            counts[4]
        ),
        "+------------+----------+".dimmed().to_string(),
        format!("| {:<10} | {:>8} |", "total".bold(), total),
        "+------------+----------+".dimmed().to_string(),
    ]
}

fn category_table_lines(findings: &[Finding]) -> Vec<String> {
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

    let mut lines = vec![
        "+------+----------------+----------+".dimmed().to_string(),
        format!(
            "| {:<4} | {:<14} | {:>8} |",
            "Code".bold(),
            "Category".bold(),
            "Count".bold()
        ),
        "+------+----------------+----------+".dimmed().to_string(),
    ];

    if rows.is_empty() {
        lines.push(format!("| {:<4} | {:<14} | {:>8} |", "-", "none", 0));
    } else {
        for (code, label, count) in rows {
            lines.push(format!(
                "| {:<4} | {:<14} | {:>8} |",
                code.bold(),
                label,
                count
            ));
        }
    }

    lines.push("+------+----------------+----------+".dimmed().to_string());
    lines
}

fn visible_width(value: &str) -> usize {
    let mut width = 0;
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
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
            remediation: "Allowlist outbound destinations and block internal address space.",
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
        assert!(rendered.contains("Scan Summary"));
        assert!(rendered.contains("Category Breakdown"));
        assert!(rendered.contains("| Severity   |    Count |"));
        assert!(rendered.contains("| Code | Category       |    Count |"));
        assert!(rendered.contains("| total      |        0 |"));
        assert!(rendered.contains("| -    | none           |        0 |"));
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
        assert!(rendered.contains("Http::get($request->input('url'));"));
        assert!(rendered.contains("Closing Summary"));
    }
}

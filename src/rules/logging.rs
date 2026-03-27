//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
use regex::Regex;

use crate::models::{Category, RuleMeta, ScanContext, Severity};
use crate::scanner::Project;

use super::make_finding;

const RULES: [RuleMeta; 3] = [
    RuleMeta {
        id: "logging.debug-leak",
        title: "Debug mode may leak stack traces",
        category: Category::Logging,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "logging.sensitive-log",
        title: "Sensitive value logged",
        category: Category::Logging,
        default_severity: Severity::High,
    },
    RuleMeta {
        id: "logging.auth-failure-missing",
        title: "No obvious auth failure logging",
        category: Category::Logging,
        default_severity: Severity::Low,
    },
];

pub fn metadata() -> Vec<RuleMeta> {
    RULES.to_vec()
}

pub fn run(project: &Project, context: &ScanContext) -> Vec<crate::models::Finding> {
    if !context.category_enabled(Category::Logging) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let log_secret_re = Regex::new(
        r"Log::(debug|info|warning|error)\s*\([^)]*(password|token|secret|authorization)",
    )
    .expect("valid regex");

    for env_file in [".env", ".env.production"] {
        if let Some(file) = project.find_file(env_file) {
            if file.content.contains("APP_DEBUG=true") {
                findings.push(make_finding(
                    RULES[0],
                    Some(&file.relative_path),
                    Some(1),
                    "Debug mode enabled in environment file",
                    "Laravel debug pages can leak stack traces, credentials, and internal paths.",
                    None,
                ));
            }
        }
    }

    for file in project.files_with_extension("php") {
        for (idx, line) in file.content.lines().enumerate() {
            if log_secret_re.is_match(&line.to_ascii_lowercase()) {
                findings.push(make_finding(
                    RULES[1],
                    Some(&file.relative_path),
                    Some(idx + 1),
                    "Sensitive data may be written to logs",
                    "Avoid logging passwords, tokens, and authorization headers even at debug level.",
                    Some(line.trim().to_string()),
                ));
            }
        }
    }

    let auth_present = !project.files_under("app/Http/Controllers/Auth/").is_empty()
        || project
            .files
            .iter()
            .any(|file| file.content.contains("Auth::attempt("));
    let has_failure_logging = project.files.iter().any(|file| {
        file.content.contains("Failed")
            || file.content.contains("Lockout")
            || file.content.contains("Login failed")
    });
    if auth_present && !has_failure_logging {
        findings.push(make_finding(
            RULES[2],
            None,
            None,
            "No obvious authentication failure logging found",
            "Consider logging authentication failures and lockouts with care so abuse patterns can be monitored without leaking credentials.",
            None,
        ));
    }

    findings
}

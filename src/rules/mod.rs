//! # `lsec`
//!
//! Laravel Security Audit CLI for scanning Laravel applications for
//! common security issues, insecure patterns, and risky configuration.
//!
//! (c) 2026 Afaan Bilal <https://afaan.dev>
//!
pub mod auth;
pub mod deps;
pub mod env;
pub mod http;
pub mod injection;
pub mod logging;
pub mod secrets;
pub mod storage;

use crate::models::{Finding, RuleMeta, ScanContext};
use crate::scanner::Project;

pub fn all_rule_metadata() -> Vec<RuleMeta> {
    let mut rules = Vec::new();
    rules.extend(env::metadata());
    rules.extend(auth::metadata());
    rules.extend(injection::metadata());
    rules.extend(http::metadata());
    rules.extend(storage::metadata());
    rules.extend(deps::metadata());
    rules.extend(secrets::metadata());
    rules.extend(logging::metadata());
    rules
}

pub fn run_rules(project: &Project, context: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(env::run(project, context));
    findings.extend(auth::run(project, context));
    findings.extend(injection::run(project, context));
    findings.extend(http::run(project, context));
    findings.extend(storage::run(project, context));
    findings.extend(deps::run(project, context));
    findings.extend(secrets::run(project, context));
    findings.extend(logging::run(project, context));
    findings.sort_by_key(|finding| (finding.severity, finding.file.clone(), finding.line));
    findings
}

fn make_finding(
    meta: RuleMeta,
    file: Option<&str>,
    line: Option<usize>,
    title: impl Into<String>,
    message: impl Into<String>,
    snippet: Option<String>,
) -> Finding {
    Finding {
        rule_id: meta.id,
        title: title.into(),
        message: message.into(),
        severity: meta.default_severity,
        category: meta.category,
        file: file.map(ToOwned::to_owned),
        line,
        snippet,
    }
}

fn find_line(content: &str, pattern: &str) -> Option<usize> {
    content
        .lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(pattern).then_some(idx + 1))
}

fn snippet_for_line(content: &str, line_number: usize) -> Option<String> {
    content
        .lines()
        .nth(line_number.saturating_sub(1))
        .map(str::trim)
        .map(str::to_string)
}
